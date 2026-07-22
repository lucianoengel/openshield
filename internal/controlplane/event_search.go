package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Event search (SIEM-1). The fleet aggregate (fleet_telemetry) held every received event,
// classification and decision, but the only ways to read it were two point-lookups —
// everything for one agent, or everything for one event id. An investigator triaging a
// correlated incident (D65/D131) needs the middle ground: "every DECISION in this window",
// "every event of this KIND for this agent", "only the VERIFIED (attributable) rows". This
// is that filtered, bounded search over the aggregate.
//
// Like the peer-alert search (SEC-8), it is PARAMETERIZED (operator input is data, never
// concatenated SQL) and hard-CAPPED (an uncapped limit over the largest table is an
// unbounded-memory vector). It returns metadata only — agent, kind, event id, verified,
// time — NOT the payload blob: a list surface that dumped every raw proto would be noisy and
// unbounded; the caller drills into a specific event id via TelemetryForEvent for the payload.

// EventFilter is a search over the fleet telemetry aggregate. Every field is optional; a zero
// field is "no constraint". VerifiedOnly restricts to attributable rows (D44) — an investigator
// building a case must be able to exclude self-asserted telemetry, which is not evidence.
type EventFilter struct {
	AgentID      string
	Kind         string // event | classification | decision ("" = any)
	EventID      string
	Since        time.Time
	Until        time.Time
	VerifiedOnly bool
	Limit        int
}

// EventRow is one telemetry row's metadata, without the payload blob.
type EventRow struct {
	AgentID    string    `json:"agent_id"`
	Kind       string    `json:"kind"`
	EventID    string    `json:"event_id"`
	Verified   bool      `json:"verified"`
	ReceivedAt time.Time `json:"received_at"`
}

// SearchTelemetry returns telemetry rows matching the filter, newest first. It builds the
// WHERE clause from only the constraints that are set, binding each as a placeholder, and
// clamps the limit to maxSearchLimit even for a direct (non-HTTP) caller.
func (s *Server) SearchTelemetry(ctx context.Context, f EventFilter) ([]EventRow, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > maxSearchLimit {
		limit = maxSearchLimit
	}

	q := `SELECT agent_id, kind, event_id, verified, received_at FROM fleet_telemetry`
	var conds []string
	var args []any
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(cond, len(args))) // $N binds the value just appended
	}
	if f.AgentID != "" {
		add("agent_id = $%d", f.AgentID)
	}
	if f.Kind != "" {
		add("kind = $%d", f.Kind)
	}
	if f.EventID != "" {
		add("event_id = $%d", f.EventID)
	}
	if !f.Since.IsZero() {
		add("received_at >= $%d", f.Since)
	}
	if !f.Until.IsZero() {
		add("received_at <= $%d", f.Until)
	}
	if f.VerifiedOnly {
		conds = append(conds, "verified = true")
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
	var out []EventRow
	for rows.Next() {
		var e EventRow
		if err := rows.Scan(&e.AgentID, &e.Kind, &e.EventID, &e.Verified, &e.ReceivedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// parseEventFilter parses the /events query params, returning an error on ANY malformed value
// (SEC-8) — a silently-dropped bad since/until/limit returns OVER-BROAD results that look
// authoritative, and an investigator would trust a wrong answer.
func parseEventFilter(r *http.Request) (EventFilter, error) {
	q := r.URL.Query()
	f := EventFilter{AgentID: q.Get("agent"), Kind: q.Get("kind"), EventID: q.Get("event")}

	if v := q.Get("verified"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return f, fmt.Errorf("verified: %w", err)
		}
		f.VerifiedOnly = b
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
		if err != nil {
			return f, fmt.Errorf("limit: %w", err)
		}
		f.Limit = n
	}
	if f.Limit > maxSearchLimit {
		f.Limit = maxSearchLimit // clamp, not error — a large ask is honored up to the cap
	}
	return f, nil
}
