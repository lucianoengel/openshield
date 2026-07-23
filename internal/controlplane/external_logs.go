package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/cef"
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
	sink := func(m syslog.Message) {
		msg, ok := cef.FromSyslog(m.Msg)
		if !ok {
			s.CEFDropped.Add(1) // a non-CEF or malformed-CEF line — this listener ingests CEF only
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
		// Best-effort persist: a DB error is counted, not fatal (a down DB must not crash the listener).
		ictx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.InsertExternalLog(ictx, e); err != nil {
			s.CEFDropped.Add(1)
			return
		}
		s.CEFIngested.Add(1)
	}
	l, err := syslog.Listen(addr, sink, nil)
	if err != nil {
		return err
	}
	s.cefListenAddr.Store(l.Addr().String())
	return l.Serve(ctx)
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
