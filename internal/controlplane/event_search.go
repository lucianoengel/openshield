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
	// Cursor continues from a previous page (CONSOLE-6). Empty starts at the newest row. It is a
	// POSITION ONLY — the caller's authority is re-derived from their credential on every page, never
	// read from here, because a cursor honoured as authority is a cursor another operator can replay.
	Cursor string
}

// EventPage is one page of a keyset walk.
type EventPage struct {
	Rows    []EventRow `json:"rows"`
	HasMore bool       `json:"has_more"`
	// NextCursor is ABSENT on the last page, never empty: a value a client could mistake for a usable
	// one must be absent, or it will be sent back. Same rule as risk on the entity surface and last-seen
	// on the fleet roster.
	NextCursor string `json:"next_cursor,omitempty"`
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
	page, err := s.SearchTelemetryPage(ctx, f)
	if err != nil {
		return nil, err
	}
	return page.Rows, nil
}

// SearchTelemetryPage is the paginated read (CONSOLE-6): the same search, plus whether more rows exist
// and where to continue.
//
// SearchTelemetry is kept as the un-paginated view for callers that want the first page and nothing else,
// so existing callers are unchanged and the two cannot disagree about what a page contains.
func (s *Server) SearchTelemetryPage(ctx context.Context, f EventFilter) (EventPage, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > maxSearchLimit {
		limit = maxSearchLimit
	}

	// `id` joins the SELECT because it is half the cursor key. It is not returned to callers — EventRow
	// stays metadata-only — but the walk cannot express a boundary without it.
	q := `SELECT agent_id, kind, event_id, verified, received_at, id FROM fleet_telemetry`
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
	// THE KEYSET BOUNDARY. Row-wise comparison against the exact ORDER BY tuple, so the walk resumes at
	// the row after the last one returned — no offset, and no dependence on rows that arrived since.
	// `(received_at, id)` is unique and monotone, which is what makes the boundary exact rather than
	// approximate: two rows sharing a timestamp are still ordered by id.
	if f.Cursor != "" {
		c, cerr := decodeEventCursor(f.Cursor)
		if cerr != nil {
			return EventPage{}, cerr
		}
		args = append(args, c.ReceivedAt, c.ID)
		conds = append(conds, fmt.Sprintf("(received_at, id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	// OVER-READ BY ONE to learn whether another page exists. A separate COUNT(*) over a 90-day
	// partition is expensive, and under live ingest it answers a different question than "is there
	// another page" — the count would already be stale by the time the page rendered.
	args = append(args, limit+1)
	q += fmt.Sprintf(" ORDER BY received_at DESC, id DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return EventPage{}, err
	}
	defer rows.Close()
	var out []EventRow
	var ids []int64 // kept alongside, because the cursor needs the id and EventRow deliberately does not carry it
	for rows.Next() {
		var e EventRow
		var id int64
		if err := rows.Scan(&e.AgentID, &e.Kind, &e.EventID, &e.Verified, &e.ReceivedAt, &id); err != nil {
			return EventPage{}, err
		}
		out = append(out, e)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return EventPage{}, err
	}

	page := EventPage{Rows: out}
	if len(out) > limit {
		// THE EXTRA ROW IS DISCARDED, never returned, so `limit` means what it says. The cursor comes
		// from the LAST RETURNED row, not the probe row — taking it from the probe would skip that row
		// on the next page.
		page.Rows = out[:limit]
		page.HasMore = true
		page.NextCursor = eventCursor{
			ReceivedAt: page.Rows[limit-1].ReceivedAt,
			ID:         ids[limit-1],
		}.encode()
	}
	if page.Rows == nil {
		page.Rows = []EventRow{} // never `null`: an empty page and an unreadable one must not look alike
	}
	return page, nil
}

// parseEventFilter parses the /events query params, returning an error on ANY malformed value
// (SEC-8) — a silently-dropped bad since/until/limit returns OVER-BROAD results that look
// authoritative, and an investigator would trust a wrong answer.
func parseEventFilter(r *http.Request) (EventFilter, error) {
	q := r.URL.Query()
	f := EventFilter{AgentID: q.Get("agent"), Kind: q.Get("kind"), EventID: q.Get("event")}

	// A kind typo returns zero rows, which reads as "nothing happened" — a wrong answer that looks
	// authoritative (the SEC-8 family). Reject an unknown kind rather than silently over-narrowing.
	if f.Kind != "" && f.Kind != "event" && f.Kind != "classification" && f.Kind != "decision" {
		return f, fmt.Errorf("kind %q is not one of event/classification/decision", f.Kind)
	}
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
		if err != nil || n <= 0 {
			// A non-positive limit is a malformed request, not "no limit" — reject it (match
			// parseAlertFilter) rather than fall through to the default and look authoritative.
			return f, fmt.Errorf("limit %q is not a positive integer", v)
		}
		f.Limit = n
	}
	if f.Limit > maxSearchLimit {
		f.Limit = maxSearchLimit // clamp, not error — a large ask is honored up to the cap
	}
	// CONSOLE-6: the continuation cursor, VALIDATED HERE so a malformed one is a 400 at the edge rather
	// than an error from the query layer. Refused, never ignored: silently restarting from the beginning
	// hands page 1 to a client that believes it is deeper, which renders duplicates and reads as the
	// data having changed underneath.
	if v := strings.TrimSpace(q.Get("cursor")); v != "" {
		if _, err := decodeEventCursor(v); err != nil {
			return f, err
		}
		f.Cursor = v
	}
	return f, nil
}
