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

// RecentPeerAlerts WAS HERE AND IS DELETED (CONSOLE-6b). /alerts was its only route, and that route now
// reads through SearchPeerAlertsPage. What was left was an exported unpaginated read carrying
// `ORDER BY detected_at DESC` with NO id tiebreaker and no maximum — the exact defect this change argued
// against and built a tie fixture to catch — sitting in the package as the obvious thing the next
// /alerts-shaped route would reach for. Kept "just for tests" it would have gone on compiling forever and
// eventually acquired a caller. An unfiltered newest-first read is `SearchPeerAlertsPage` with an empty
// AlertFilter; there is nothing this offered that that does not.

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
	// Cursor continues from a previous page (CONSOLE-6b). Empty starts at the newest alert. It is a
	// POSITION ONLY — the caller's authority is re-derived from their credential on every page, never
	// read from here, because a cursor honoured as authority is a cursor another operator can replay.
	Cursor string
}

// AlertPage is one page of a keyset walk over peer_alerts.
type AlertPage struct {
	Rows    []PeerAlert `json:"rows"`
	HasMore bool        `json:"has_more"`
	// NextCursor is ABSENT on the last page, never empty: a value a client could mistake for a usable
	// one must be absent, or it will be sent back and an empty page rendered as a real one.
	NextCursor string `json:"next_cursor,omitempty"`
}

// SearchPeerAlerts returns peer alerts matching the filter, newest first. It builds the
// WHERE clause from only the constraints that are set, binding each as a placeholder — the
// operator's values are DATA, never SQL. This is the F1 search over the fleet aggregate,
// the substrate a SIEM UI queries.
//
// Kept as the un-paginated view for callers that want the first page and nothing else (the saved-search
// runner, and every test that just wants the rows), so those callers are unchanged and the two views
// cannot disagree about what a page contains.
func (s *Server) SearchPeerAlerts(ctx context.Context, f AlertFilter) ([]PeerAlert, error) {
	page, err := s.SearchPeerAlertsPage(ctx, f)
	if err != nil {
		return nil, err
	}
	return page.Rows, nil
}

// SearchPeerAlertsPage is the paginated read (CONSOLE-6b): the same search, plus whether more rows exist
// and where to continue. Both /alerts and /search read through it, so the alert queue and the filtered
// hunt cannot end up with different ideas of what a page is.
func (s *Server) SearchPeerAlertsPage(ctx context.Context, f AlertFilter) (AlertPage, error) {
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
	// THE KEYSET BOUNDARY, appended after every other constraint. Row-wise comparison against the exact
	// ORDER BY tuple, so the walk resumes at the row after the last one returned — no offset, and no
	// dependence on rows written since. `id` is half the key and not decoration: a detector pass writes
	// several alerts sharing one detected_at, and a boundary on the timestamp alone would step past the
	// whole tied group, losing every row in it for the rest of the walk.
	if f.Cursor != "" {
		c, cerr := decodeAlertCursor(f.Cursor)
		if cerr != nil {
			return AlertPage{}, cerr
		}
		args = append(args, c.DetectedAt, c.ID)
		conds = append(conds, fmt.Sprintf("(detected_at, id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	// OVER-READ BY ONE to learn whether another page exists. A separate COUNT(*) is a second scan of the
	// same predicate, and under live detection it answers a different question than "is there another
	// page" — the count is already stale by the time the page renders.
	args = append(args, limit+1)
	q += fmt.Sprintf(" ORDER BY detected_at DESC, id DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return AlertPage{}, err
	}
	defer rows.Close()
	var out []PeerAlert
	for rows.Next() {
		a, err := scanPeerAlert(rows)
		if err != nil {
			return AlertPage{}, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return AlertPage{}, err
	}

	page := AlertPage{Rows: out}
	if len(out) > limit {
		// THE EXTRA ROW IS DISCARDED, never returned, so `limit` means what it says. The cursor comes
		// from the LAST RETURNED row and not the probe row — taking it from the probe would skip that
		// row on the next page. PeerAlert already carries its id, so unlike the event walk there is no
		// parallel id slice to keep in step.
		page.Rows = out[:limit]
		page.HasMore = true
		last := page.Rows[limit-1]
		page.NextCursor = alertCursor{DetectedAt: last.DetectedAt, ID: last.ID}.encode()
	}
	if page.Rows == nil {
		page.Rows = []PeerAlert{} // never `null`: an empty page and a failed read must not look alike
	}
	return page, nil
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
		// CONSOLE-6b: the queue is WALKABLE. It reads through the same page function /search uses, so
		// the two surfaces cannot disagree about what a page is, and a client that has paged one has
		// paged the other. Authority is re-derived per page from the credential the tier gate already
		// checked on THIS request (D470) — the cursor carries a position and nothing else.
		f := AlertFilter{Limit: limit}
		if v := strings.TrimSpace(r.URL.Query().Get("cursor")); v != "" {
			// Validated at the edge so an unreadable cursor is a 400 here rather than an error surfacing
			// from the query layer as a 500. Refused, never ignored: silently serving page 1 to a client
			// that believes it is deeper makes it render duplicates and conclude the data changed under it.
			if _, cerr := decodeAlertCursor(v); cerr != nil {
				http.Error(w, "bad cursor: "+cerr.Error(), http.StatusBadRequest)
				return
			}
			f.Cursor = v
		}
		page, err := s.SearchPeerAlertsPage(r.Context(), f)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, page)
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
		// CONSOLE-6b: a PAGE, not a bare list. The filtered hunt was the surface most likely to hit the
		// 1000-row cap and the one least able to survive doing so silently.
		page, err := s.SearchPeerAlertsPage(r.Context(), f)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, page)
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
		// CONSOLE-6: a PAGE, not a bare list — rows plus whether more exist plus where to continue.
		//
		// AUTHORITY IS RE-DERIVED PER PAGE and never read from the cursor. The tier gate ran on THIS
		// request with THIS credential before the handler was reached (D470 puts the principal on the
		// context), so a cursor lifted from another operator's session yields that operator's POSITION
		// and the lifter's AUTHORITY. That is the CONSOLE-1 inherited requirement, and it holds because
		// the cursor carries a position and nothing else — not because anything here checks it.
		page, err := s.SearchTelemetryPage(r.Context(), f)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, page)
	})

	mux.HandleFunc("/logs", s.externalLogsHandler)
	mux.HandleFunc("/logs/fields", s.logFieldsHandler)                // SIEM-13: the canonical hunting vocabulary and what it covers                    // SIEM-4: search ingested third-party logs (CEF, CloudTrail)
	mux.HandleFunc("/compliance/retention", s.retentionReportHandler) // SIEM-10: retention compliance report

	mux.HandleFunc("/alerts/ack", s.alertAckHandler)

	// SIEM-14: saved searches. Listing and running are reads; writing one is not, because a saved
	// search is a tool the whole team will run and trust.
	mux.HandleFunc("/searches", s.savedSearchHandler)
	mux.HandleFunc("/searches/save", s.savedSearchSaveHandler)
	mux.HandleFunc("/searches/run", s.savedSearchRunHandler)
	mux.HandleFunc("/searches/delete", s.savedSearchDeleteHandler)

	mux.HandleFunc("/subject", s.subjectHandler)
	mux.HandleFunc("/views", s.viewAuditHandler) // CONSOLE-1: who viewed what — the privacy officer's route
	mux.HandleFunc("/health", s.healthHandler)   // CONSOLE-7: can this console trust the answers it is getting
	// CONSOLE-8: the roster, and the register of what has been used to stop the product.
	mux.HandleFunc("/fleet", s.fleetHandler)
	mux.HandleFunc("/fleet/controls", s.fleetControlsHandler)
	// CONSOLE-9: the device⋈user graph and its risk — the analyst's pivot from an alert.
	mux.HandleFunc("/entities", s.entitiesHandler)

	mux.HandleFunc("/incidents", s.incidentsHandler)
	mux.HandleFunc("/incidents/ack", s.incidentAckHandler)
	mux.HandleFunc("/incidents/transition", s.incidentTransitionHandler)   // SOAR-2: advance the lifecycle
	mux.HandleFunc("/incidents/timeline", s.incidentTimelineHandler)       // XDR-5: an incident's contributing alerts + evidence refs
	mux.HandleFunc("/incidents/recurrences", s.incidentRecurrencesHandler) // SOAR-2b: every time this trouble came back
	mux.HandleFunc("/correlate/backfill", s.backfillHandler)               // SOAR-10: correlate a historical range
	mux.HandleFunc("/report/response", s.responseReportHandler)            // SOAR-6: MTTA/MTTR + detection latency
	// D290: the case and approval WRITE surface. Until this, every one of these operations existed,
	// was tested, and had no caller — a playbook could open a case and a human could not, and the
	// four-eyes case closure could not be exercised at all.
	s.caseWriteHandlers(mux)
	// D291: response intents (SOAR-7 Tier-2). The IdP responder was already wired and verifying; until
	// this there was nothing that could publish an intent for it to verify.
	s.intentHandlers(mux)
	// D292: the configuration surface. Until this, the database was authoritative for every dynamic
	// setting and nothing in the product could write one.
	s.configHandlers(mux)

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
	// CONSOLE-6b: the continuation cursor, DECODED HERE ONLY TO VALIDATE IT — the encoded form is what
	// the query layer carries, so this is a check and not a parse whose result is used. A malformed one
	// is then a 400 at the edge like every other bad param on this surface, and a cursor minted for
	// another walk (an /events or /incidents position) fails the same check rather than being honoured
	// against peer_alerts, where it would serve a wrong-but-plausible page.
	if v := strings.TrimSpace(q.Get("cursor")); v != "" {
		if _, err := decodeAlertCursor(v); err != nil {
			return AlertFilter{}, err
		}
		f.Cursor = v
	}
	return f, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
