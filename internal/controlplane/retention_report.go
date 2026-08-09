package controlplane

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RetentionEvent is one recorded retention purge (SIEM-10): the compliance evidence that data past a
// retention window was deleted — what, how much, the boundary applied, the policy, and when.
type RetentionEvent struct {
	PurgedAt     time.Time
	Target       string // fleet_telemetry | notify_dedupe | …
	RowsAffected int64
	Cutoff       time.Time // the retention boundary applied
	Policy       string    // the human-readable driver (the configured window)
}

// RecordRetentionEvent records a retention purge as a compliance event (SIEM-10). It is BEST-EFFORT: a
// failure is counted (RetentionRecordFailures) and logged, never returned — the purge already happened
// (it cannot be un-done), and failing the retention loop would be worse. A zero-row purge is recorded
// too, so the report proves retention is EXECUTING on schedule, not only that rows were deleted.
//
// IT IS CALLED FROM THE RETENTION LOOP, so its counter is a leader loop's counter and is bound by the
// same stop rule as the six in this package: on a demotion or a shutdown this Exec fails with
// `context.Canceled` and `openshield_retention_record_failures_total` moved for a routine event.
//
// `loopCtx` MUST BE THE LOOP'S OWN CONTEXT, and this is the one site in the seven that cannot verify it
// locally — the other six name `ctx` in their own loop function, while this one is handed whatever
// `runRetentionSweep` was given. Today that IS the loop context, because `retain.Loop` passes its ctx
// straight through to the work function and the work function passes it straight to the sweep. If a
// future change gives the sweep a DERIVED per-tick context (a per-tick timeout, say), this parameter
// silently becomes the wrong one while the other six keep working — the stop would then be counted here
// and nowhere else. The parameter is named for what it must be so that change is visible when it is made.
//
// NOTE FOR THE GUARD: this increment lives in a method CALLED FROM the loop literal, not inside it, so
// the lexical check in loop_guard_test.go cannot see it. It was found and fixed by review. The obligation
// is universal; the build-time check is not, and the spec says so rather than implying otherwise.
func (s *Server) RecordRetentionEvent(loopCtx context.Context, log *slog.Logger, target string, rows int64, cutoff time.Time, policy string) {
	var cut interface{}
	if !cutoff.IsZero() {
		cut = cutoff.UTC()
	}
	if _, err := s.pool.Exec(loopCtx,
		`INSERT INTO retention_events (target, rows_affected, cutoff, policy) VALUES ($1,$2,$3,$4)`,
		target, rows, cut, policy); err != nil {
		NoteTickErr(loopCtx, log, "recording retention event failed (the purge still happened)",
			&s.RetentionRecordFailures, err, slog.String("target", target))
	}
}

// RetentionReportFilter narrows the compliance report. Empty/zero fields are unfiltered; Limit capped.
type RetentionReportFilter struct {
	Target string
	Since  time.Time
	Until  time.Time
	Limit  int
}

// RetentionReport returns recorded retention purges, newest first, bounded — the SIEM-10 compliance
// report a query surface exposes.
func (s *Server) RetentionReport(ctx context.Context, f RetentionReportFilter) ([]RetentionEvent, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > maxSearchLimit {
		limit = maxSearchLimit
	}
	q := `SELECT purged_at, target, rows_affected, cutoff, policy FROM retention_events`
	var conds []string
	var args []any
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if f.Target != "" {
		add("target = $%d", f.Target)
	}
	if !f.Since.IsZero() {
		add("purged_at >= $%d", f.Since)
	}
	if !f.Until.IsZero() {
		add("purged_at <= $%d", f.Until)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY purged_at DESC, id DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RetentionEvent
	for rows.Next() {
		var e RetentionEvent
		var cutoff *time.Time
		if err := rows.Scan(&e.PurgedAt, &e.Target, &e.RowsAffected, &cutoff, &e.Policy); err != nil {
			return nil, err
		}
		if cutoff != nil {
			e.Cutoff = *cutoff
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// retentionReportHandler serves GET /compliance/retention — the SIEM-10 compliance report over recorded
// retention purges. RoleAnalyst-gated by the mount. A malformed filter is a 400 (SEC-8), not a silently
// over-broad compliance answer.
func (s *Server) retentionReportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	f, err := parseRetentionFilter(r)
	if err != nil {
		http.Error(w, "bad filter: "+err.Error(), http.StatusBadRequest)
		return
	}
	events, err := s.RetentionReport(r.Context(), f)
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, events)
}

func parseRetentionFilter(r *http.Request) (RetentionReportFilter, error) {
	q := r.URL.Query()
	f := RetentionReportFilter{Target: q.Get("target")}
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
	return f, nil
}
