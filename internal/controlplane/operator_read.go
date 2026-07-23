package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// PeerAlert is one server-side peer-UEBA detection, as an operator reads it. The
// subject is pseudonymous (D23) and there is no content — a peer alert is the
// control plane's own fleet-aggregate detection (D54), not evidence.
type PeerAlert struct {
	ID             int64      `json:"id"`
	SubjectID      string     `json:"subject_id"`
	RiskScore      float64    `json:"risk_score"`
	Severity       string     `json:"severity"`  // stored triage bucket, stamped at write (SIEM-6b/ADR-10)
	Status         string     `json:"status"`    // lifecycle: open -> triaged -> closed (SIEM-6b)
	DedupKey       string     `json:"dedup_key"` // detector-namespaced correlation key (SIEM-6b)
	ContextVersion string     `json:"context_version"`
	AgentID        string     `json:"agent_id"` // originating host of the triggering event (SIEM-2); "" if pre-identity
	DetectedAt     time.Time  `json:"detected_at"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"` // verified operator who triaged it (SIEM-6); "" if unacknowledged
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
}

// peerAlertColumns is the shared SELECT list, so every read of peer_alerts returns the same
// shape and the scan below stays in lockstep with it.
const peerAlertColumns = `id, subject_id, risk_score, context_version, agent_id, detected_at, acknowledged_by, acknowledged_at, severity, status, dedup_key`

// scanPeerAlert scans one row in peerAlertColumns order. Severity/status/dedup_key are STORED
// first-class fields (SIEM-6b/ADR-10), read from the columns rather than derived here.
func scanPeerAlert(rows interface{ Scan(...any) error }) (PeerAlert, error) {
	var a PeerAlert
	if err := rows.Scan(&a.ID, &a.SubjectID, &a.RiskScore, &a.ContextVersion, &a.AgentID, &a.DetectedAt, &a.AcknowledgedBy, &a.AcknowledgedAt, &a.Severity, &a.Status, &a.DedupKey); err != nil {
		return a, err
	}
	return a, nil
}

// RecentPeerAlerts returns the most recent peer alerts, newest first.
func (s *Server) RecentPeerAlerts(ctx context.Context, limit int) ([]PeerAlert, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+peerAlertColumns+` FROM peer_alerts ORDER BY detected_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PeerAlert
	for rows.Next() {
		a, err := scanPeerAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AlertFilter is a search query over the fleet's peer alerts (Phase F1). Every field is
// optional; a zero field is "no constraint". The filter is applied as PARAMETERIZED SQL —
// operator input is never concatenated into the query, so the search surface is not a SQL
// injection vector.
type AlertFilter struct {
	SubjectID          string    // exact pseudonymous subject, or "" for any
	MinRisk            float64   // only alerts at or above this risk
	MinSeverity        string    // only alerts at or above this severity bucket (SIEM-6); "" = no constraint
	UnacknowledgedOnly bool      // only alerts not yet acknowledged — the actionable queue (SIEM-6)
	Since              time.Time // only alerts at or after this time (zero = no lower bound)
	Until              time.Time // only alerts at or before this time (zero = no upper bound)
	Limit              int       // max rows (default 100)
}

// SearchPeerAlerts returns peer alerts matching the filter, newest first. It builds the
// WHERE clause from only the constraints that are set, binding each as a placeholder — the
// operator's values are DATA, never SQL. This is the F1 search over the fleet aggregate,
// the substrate a SIEM UI queries.
func (s *Server) SearchPeerAlerts(ctx context.Context, f AlertFilter) ([]PeerAlert, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > maxSearchLimit {
		limit = maxSearchLimit // SEC-8: hard cap even for a direct (non-HTTP) caller
	}
	q := `SELECT ` + peerAlertColumns + ` FROM peer_alerts`
	var conds []string
	var args []any
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(cond, len(args))) // $N binds the value just appended
	}
	if f.SubjectID != "" {
		add("subject_id = $%d", f.SubjectID)
	}
	// A min-severity constraint is applied as a risk floor (severity is derived from risk), and
	// combined with an explicit MinRisk by taking the STRONGER (higher) of the two — asking for
	// "high" must not widen a stricter MinRisk already set.
	riskFloor := f.MinRisk
	if f.MinSeverity != "" {
		if sf, ok := severityFloor(f.MinSeverity); ok && sf > riskFloor {
			riskFloor = sf
		}
	}
	if riskFloor > 0 {
		add("risk_score >= $%d", riskFloor)
	}
	if f.UnacknowledgedOnly {
		conds = append(conds, "acknowledged_at IS NULL")
	}
	if !f.Since.IsZero() {
		add("detected_at >= $%d", f.Since)
	}
	if !f.Until.IsZero() {
		add("detected_at <= $%d", f.Until)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY detected_at DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PeerAlert
	for rows.Next() {
		a, err := scanPeerAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// OperatorReadHandler serves the operator's read surface over the fleet: recent peer
// alerts (/alerts), a filtered search (/search), and overdue agents (/overdue). It is
// mounted behind the operator-role gate (D82); it holds no signer and can forge nothing (D30).
func (s *Server) OperatorReadHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// SEC-8: a malformed limit is a 400, not a silent default (matches /search and /incidents).
		limit, err := intParam(r.URL.Query(), "limit", 100)
		if err != nil {
			http.Error(w, "bad limit: "+err.Error(), http.StatusBadRequest)
			return
		}
		alerts, err := s.RecentPeerAlerts(r.Context(), limit)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, alerts)
	})

	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// SEC-8: a malformed filter param is a 400, NOT a silent drop — silently ignoring a
		// bad since/until/min_risk returns OVER-BROAD results that look authoritative (an
		// investigator would trust a wrong answer).
		f, err := parseAlertFilter(r)
		if err != nil {
			http.Error(w, "bad filter: "+err.Error(), http.StatusBadRequest)
			return
		}
		alerts, err := s.SearchPeerAlerts(r.Context(), f)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, alerts)
	})

	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// SEC-8: a malformed filter param is a 400, not a silent drop — silently ignoring a
		// bad since/until/limit returns over-broad results an investigator would trust.
		f, err := parseEventFilter(r)
		if err != nil {
			http.Error(w, "bad filter: "+err.Error(), http.StatusBadRequest)
			return
		}
		events, err := s.SearchTelemetry(r.Context(), f)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, events)
	})

	mux.HandleFunc("/logs", s.externalLogsHandler) // SIEM-4: search ingested third-party logs (CEF, CloudTrail)
	mux.HandleFunc("/compliance/retention", s.retentionReportHandler) // SIEM-10: retention compliance report

	mux.HandleFunc("/alerts/ack", s.alertAckHandler)

	mux.HandleFunc("/subject", s.subjectHandler)

	mux.HandleFunc("/incidents", s.incidentsHandler)
	mux.HandleFunc("/incidents/ack", s.incidentAckHandler)

	mux.HandleFunc("/overdue", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		threshold := 15 * time.Minute
		if v := r.URL.Query().Get("threshold"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				// SEC-8: a malformed threshold is a 400, not a silent fall-back to the default.
				http.Error(w, "bad threshold: "+err.Error(), http.StatusBadRequest)
				return
			}
			threshold = d
		}
		overdue, err := s.Overdue(r.Context(), threshold, time.Now())
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, overdue)
	})

	return mux
}

// maxSearchLimit caps a /search result set (SEC-8): an uncapped limit is an unbounded
// query / memory vector. A caller may ask for less; more is clamped.
const maxSearchLimit = 1000

// parseAlertFilter parses the /search query params, returning an error on ANY malformed
// value (SEC-8) rather than silently dropping it, and capping the limit.
func parseAlertFilter(r *http.Request) (AlertFilter, error) {
	q := r.URL.Query()
	f := AlertFilter{SubjectID: q.Get("subject")}

	limit := 100
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return AlertFilter{}, fmt.Errorf("limit %q is not a positive integer", v)
		}
		limit = n
	}
	if limit > maxSearchLimit {
		limit = maxSearchLimit // clamp, not error — a large ask is honored up to the cap
	}
	f.Limit = limit

	if v := q.Get("min_risk"); v != "" {
		x, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return AlertFilter{}, fmt.Errorf("min_risk %q is not a number", v)
		}
		f.MinRisk = x
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return AlertFilter{}, fmt.Errorf("since %q is not RFC3339 time", v)
		}
		f.Since = t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return AlertFilter{}, fmt.Errorf("until %q is not RFC3339 time", v)
		}
		f.Until = t
	}
	if v := q.Get("min_severity"); v != "" {
		if _, ok := severityFloor(v); !ok {
			return AlertFilter{}, fmt.Errorf("min_severity %q is not one of critical/high/medium/low", v)
		}
		f.MinSeverity = v
	}
	if v := q.Get("unacknowledged"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return AlertFilter{}, fmt.Errorf("unacknowledged %q is not a boolean", v)
		}
		f.UnacknowledgedOnly = b
	}
	return f, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
