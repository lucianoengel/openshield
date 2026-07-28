package controlplane

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/cef"
	"github.com/lucianoengel/openshield/internal/connectors/rfc5424"
	"github.com/lucianoengel/openshield/internal/connectors/syslog"
)

// externalLogsHandler serves GET /logs — a filtered, bounded search over the ingested third-party
// external logs (CEF over syslog, AWS CloudTrail). Mounted behind the same analyst read gate as
// /events. A malformed filter param is a 400, not a silent drop (SEC-8): silently ignoring a bad
// since/until/limit returns OVER-BROAD results an investigator would trust as authoritative.
func (s *Server) externalLogsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	f, err := parseExternalLogFilter(r)
	if err != nil {
		http.Error(w, "bad filter: "+err.Error(), http.StatusBadRequest)
		return
	}
	logs, err := s.SearchExternalLogs(r.Context(), f)
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, logs)
}

// parseExternalLogFilter parses the /logs query params, rejecting ANY malformed value (SEC-8).
func parseExternalLogFilter(r *http.Request) (ExternalLogFilter, error) {
	q := r.URL.Query()
	f := ExternalLogFilter{
		Vendor:   q.Get("vendor"),
		Product:  q.Get("product"),
		Host:     q.Get("host"),
		Severity: q.Get("severity"),
	}
	if v := q.Get("since"); v != "" {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return f, fmt.Errorf("since: %w", err)
		}
		f.Since = ts
	}
	if v := q.Get("until"); v != "" {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return f, fmt.Errorf("until: %w", err)
		}
		f.Until = ts
	}
	f.Limit = 100
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return f, fmt.Errorf("limit %q is not a positive integer", v)
		}
		f.Limit = n
	}
	// Field-level hunting: ?field=key:value restricts to logs whose parsed fields contain that exact
	// key=value. A missing colon or an empty key is a 400 (SEC-8) — a silently-ignored field filter
	// returns over-broad results an investigator would trust.
	if v := q.Get("field"); v != "" {
		key, val, ok := strings.Cut(v, ":")
		if !ok || key == "" {
			return f, fmt.Errorf("field %q must be key:value with a non-empty key", v)
		}
		f.FieldKey, f.FieldValue = key, val
	}
	return f, nil
}

// ExternalLog is one persisted third-party log event (SIEM-4): a CEF record received over syslog from
// the estate. It is UNVERIFIED (third-party, unauthenticated syslog), stored apart from attributable
// signed telemetry — SourceHost is the sender as reported, ReceivedAt is when we received it.
type ExternalLog struct {
	ReceivedAt  time.Time
	SourceHost  string
	Vendor      string
	Product     string
	SignatureID string
	Name        string
	Severity    string
	Message     string
	Raw         string
	// Fields are the parsed per-event key/values (CEF extensions, WEF EventData, CloudTrail's fields),
	// stored as JSONB so an analyst can hunt on any of them across all sources (SIEM field-level hunting).
	Fields map[string]string
}

// ExternalLogFilter narrows an external-log search. A zero Since/Until is unbounded on that side; an
// empty field is not filtered. Limit is capped at maxSearchLimit.
type ExternalLogFilter struct {
	Vendor   string
	Product  string
	Host     string
	Severity string
	Since    time.Time
	Until    time.Time
	Limit    int
	// FieldKey/FieldValue, when both set, restrict to logs whose parsed fields contain that exact
	// key=value (`fields->>key = value`) — a hunt on any parsed field, across every source.
	FieldKey   string
	FieldValue string
}

// InsertExternalLog persists one parsed external log.
func (s *Server) InsertExternalLog(ctx context.Context, e ExternalLog) error {
	when := e.ReceivedAt
	if when.IsZero() {
		when = s.now()
	}
	fields := []byte("{}")
	if len(e.Fields) > 0 {
		if b, err := json.Marshal(e.Fields); err == nil {
			fields = b
		}
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO external_logs (received_at, source_host, vendor, product, signature_id, name, severity, message, raw, fields)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		when.UTC(), e.SourceHost, e.Vendor, e.Product, e.SignatureID, e.Name, e.Severity, e.Message, e.Raw, fields)
	return err
}

// SearchExternalLogs returns matching external logs, newest first, bounded by maxSearchLimit — the
// query capability an /logs HTTP handler (a follow-on) would expose.
func (s *Server) SearchExternalLogs(ctx context.Context, f ExternalLogFilter) ([]ExternalLog, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > maxSearchLimit {
		limit = maxSearchLimit
	}
	q := `SELECT received_at, source_host, vendor, product, signature_id, name, severity, message, raw, fields FROM external_logs`
	var conds []string
	var args []any
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if f.Vendor != "" {
		add("vendor = $%d", f.Vendor)
	}
	if f.Product != "" {
		add("product = $%d", f.Product)
	}
	if f.Host != "" {
		add("source_host = $%d", f.Host)
	}
	if f.Severity != "" {
		add("severity = $%d", f.Severity)
	}
	if f.FieldKey != "" && f.FieldValue != "" {
		// A parameterized JSONB member match: `fields->>$key = $value`. The key is a bind param (the ->>
		// operator takes it as text), so there is no SQL-injection surface. Two args in fixed order.
		args = append(args, f.FieldKey, f.FieldValue)
		conds = append(conds, fmt.Sprintf("fields->>$%d = $%d", len(args)-1, len(args)))
	}
	if !f.Since.IsZero() {
		add("received_at >= $%d", f.Since)
	}
	if !f.Until.IsZero() {
		add("received_at <= $%d", f.Until)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY received_at DESC, id DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExternalLog
	for rows.Next() {
		var e ExternalLog
		var fieldsJSON []byte
		if err := rows.Scan(&e.ReceivedAt, &e.SourceHost, &e.Vendor, &e.Product, &e.SignatureID,
			&e.Name, &e.Severity, &e.Message, &e.Raw, &fieldsJSON); err != nil {
			return nil, err
		}
		if len(fieldsJSON) > 0 {
			_ = json.Unmarshal(fieldsJSON, &e.Fields) // a bad blob leaves Fields nil, never fails the read
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RunCEFSyslog runs a CEF-over-syslog listener at addr until ctx is done, persisting each parsed CEF
// event as a searchable external-log record (SIEM-4). It composes the existing hardened syslog listener
// (bounded line, rate limiting, panic recovery) with the CEF extractor: a datagram that is not CEF, or
// whose persistence fails, is COUNTED (CEFDropped) and skipped, never crashing the listener — best-
// effort ingest of an external feed, availability over completeness. Runs on the leader only.
func (s *Server) RunCEFSyslog(ctx context.Context, addr string) error {
	l, err := syslog.Listen(addr, s.cefSink(), nil)
	if err != nil {
		return err
	}
	s.cefListenAddr.Store(l.Addr().String())
	// PUBLISHED SO ITS DISCARD COUNTERS ARE READABLE. The listener counts what it refused before the
	// message ever became a countable event — an admission-limited datagram never reaches CEFDropped,
	// so without this a flood is indistinguishable from silence (D348).
	s.cefDatagram.Store(l)
	return l.Serve(ctx)
}

// RunCEFSyslogStream serves the SAME sink over a stream transport — TCP, or TLS when a config is given
// (D337).
//
// One sink, two transports, deliberately: a second copy of the CEF/RFC-5424 reading is how the two would
// come to disagree about what a message MEANS, which is the drift the IOC store and the inline NIPS
// engine were made to share a matcher to avoid. What differs between them is delivery, not meaning.
func (s *Server) RunCEFSyslogStream(ctx context.Context, addr string, tlsConf *tls.Config) error {
	l, err := syslog.ListenStream(addr, s.cefSink(), tlsConf, nil)
	if err != nil {
		return err
	}
	s.cefStream.Store(l)
	return l.Serve(ctx)
}

// cefSink reads a syslog message as CEF, falling back to RFC 5424, and persists it as an external log.
func (s *Server) cefSink() func(syslog.Message) {
	return func(m syslog.Message) {
		msg, ok := cef.FromSyslog(m.Msg)
		if !ok {
			// SIEM-9: not CEF — try modern syslog (RFC 5424) before giving up. One listener accepting
			// both is deliberate: an estate rarely emits one format, and making an operator run a second
			// port per format is how log sources end up not onboarded at all.
			//
			// CEF is tried FIRST because a CEF payload is normally carried INSIDE a syslog line, so a
			// message can legitimately be both — and the CEF reading is the more specific one.
			if e, rok := rfc5424Log(m); rok {
				s.persistExternalLog(e)
				return
			}
			s.CEFDropped.Add(1) // neither format parsed
			return
		}
		host := m.Host // the syslog-reported sender
		e := ExternalLog{
			SourceHost:  host,
			Vendor:      msg.Vendor,
			Product:     msg.Product,
			SignatureID: msg.SignatureID,
			Name:        msg.Name,
			Severity:    msg.Severity,
			Message:     extensionMessage(msg),
			Raw:         cefMarkerLine(m.Msg),
			Fields:      msg.Extensions, // the CEF key=value extension, huntable per-field
		}
		s.persistExternalLog(e)
	}
}

// CEFListenAddr reports the bound address of the running CEF-syslog listener (":0" resolves to a real
// port), for tests and logging. Empty until RunCEFSyslog binds.
func (s *Server) CEFListenAddr() string {
	if v, ok := s.cefListenAddr.Load().(string); ok {
		return v
	}
	return ""
}

// extensionMessage picks a human-readable message for the row: CEF's `msg` extension if present, else
// the event name. (The full extension map is preserved in Raw for follow-on field-level hunting.)
func extensionMessage(m cef.Message) string {
	if v := m.Extensions["msg"]; v != "" {
		return v
	}
	return m.Name
}

// cefMarkerLine returns the CEF payload (from the CEF: marker) as the stored raw line — the syslog
// header is dropped (received_at/source_host capture it), the CEF fidelity is kept.
func cefMarkerLine(syslogMsg string) string {
	if i := strings.Index(syslogMsg, "CEF:"); i >= 0 {
		return syslogMsg[i:]
	}
	return syslogMsg
}

// rfc5424Log maps a modern-syslog line onto the same ExternalLog shape CEF produces, so both are hunted
// with one query rather than two.
//
// Vendor/Product are the APP-NAME rather than invented: RFC 5424 has no vendor concept, and filling those
// columns with a guess would make a cross-source filter silently wrong. Structured data becomes `fields`,
// which is the point — an SD element and a CEF extension are then the same searchable key/value.
func rfc5424Log(m syslog.Message) (ExternalLog, bool) {
	// Parse the RAW line: syslog.Parse deliberately strips structured data to leave Msg as free text, so
	// the fields this exists to capture are not in Msg at all. Re-parsing the raw line is the only way to
	// see them without teaching the framing layer a second job.
	msg, err := rfc5424.Parse(m.Raw)
	if err != nil {
		return ExternalLog{}, false
	}
	host := msg.Hostname
	if host == "" {
		host = m.Host // fall back to the transport-reported sender
	}
	return ExternalLog{
		SourceHost:  host,
		Vendor:      "syslog",
		Product:     msg.AppName,
		SignatureID: msg.MsgID,
		Name:        msg.AppName,
		Severity:    rfc5424.SeverityName(msg.Severity),
		Message:     msg.Message,
		Raw:         m.Msg,
		Fields:      msg.StructuredData,
	}, true
}

// persistExternalLog stores one parsed record. Best-effort: a DB error is COUNTED, not fatal — a down
// database must not crash a listener that other sources are still sending to.
func (s *Server) persistExternalLog(e ExternalLog) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.InsertExternalLog(ctx, e); err != nil {
		s.CEFDropped.Add(1)
		return
	}
	s.CEFIngested.Add(1)
}
