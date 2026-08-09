package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/lucianoengel/openshield/internal/retain"
)

// The incident lifecycle (SOAR-2, extending ADR-10).
//
// FORWARD-ONLY, deliberately. MTTA/MTTR (SOAR-6) are derived from these timestamps, and a lifecycle that
// can move backwards makes them unmeasurable — "acknowledged at" means nothing if an incident can return to
// open. An incident that needs reopening becomes a NEW incident, which the partial-unique-on-open indexes
// already allow once the old one has left `open`.
//
// `acknowledged` stays the first post-open state rather than being renamed to `triaged`: it exists in live
// rows with first-ack-wins semantics (SIEM-11b), and renaming a stored state is a migration of MEANING, not
// of schema.
const (
	IncidentOpen         = "open"
	IncidentAcknowledged = "acknowledged"
	IncidentTriaged      = "triaged"
	IncidentContained    = "contained"
	IncidentClosed       = "closed"
)

var incidentRank = map[string]int{
	IncidentOpen: 0, IncidentAcknowledged: 1, IncidentTriaged: 2, IncidentContained: 3, IncidentClosed: 4,
}

var (
	// ErrUnknownState names a target outside the lifecycle — refused rather than stored, so an operator
	// cannot invent a state that later code will not understand.
	ErrUnknownState = errors.New("controlplane: not an incident lifecycle state")
	// ErrBackwardTransition is a move to an earlier (or equal) state.
	ErrBackwardTransition = errors.New("controlplane: the incident lifecycle is forward-only")
)

// TransitionIncident advances an incident, recording who did it and when.
//
// The rank comparison happens in the UPDATE's WHERE clause, so two concurrent transitions cannot both
// apply: the second sees the already-advanced state and affects no rows.
func (s *Server) TransitionIncident(ctx context.Context, id int64, to, operator string) error {
	rank, ok := incidentRank[to]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownState, to)
	}
	if operator == "" {
		return ErrNoViewer
	}
	// The CASE mirrors incidentRank in SQL so the comparison is atomic with the write.
	//
	// SOAR-6: the first move OFF `open` also records the acknowledgement. Before this, an operator who
	// transitioned straight to `triaged` left `acknowledged_at` NULL forever, so that incident could
	// never be measured for time-to-acknowledge — the exact outcome the forward-only lifecycle exists to
	// prevent (D250). COALESCE means an existing acknowledgement is NEVER overwritten, so first-ack-wins
	// attribution (SIEM-11b) is preserved: the recorded acknowledger stays whoever actually got there
	// first. The stamp is atomic with the transition, so a refused (backward) move records nothing.
	tag, err := s.pool.Exec(ctx,
		`UPDATE incidents SET state = $1, transitioned_by = $2, transitioned_at = now(), updated_at = now(),
		        acknowledged_by = COALESCE(NULLIF(acknowledged_by, ''), $2),
		        acknowledged_at = COALESCE(acknowledged_at, now())
		  WHERE id = $3
		    AND CASE state WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 WHEN 'triaged' THEN 2
		                   WHEN 'contained' THEN 3 WHEN 'closed' THEN 4 ELSE -1 END < $4`,
		to, operator, id, rank)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Nothing moved: either the incident does not exist, or the target is not forward of where it is.
	var state string
	if err := s.pool.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, id).Scan(&state); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrIncidentNotFound
		}
		return err
	}
	return fmt.Errorf("%w: %s → %s", ErrBackwardTransition, state, to)
}

// CorrelationFailures counts scheduled correlation runs that errored — a silent loop is a loop nobody
// notices has stopped detecting.
var CorrelationFailures atomic.Int64

// RunCorrelationLoop materializes BOTH correlation rules on an interval (SOAR-2).
//
// Before this, both materializers were called from exactly one place: the GET /incidents handler. An
// incident therefore existed only if a human happened to look, which made SOAR-1's "pages automatically"
// (D220) automatic only in the sense that the page followed the materialization someone else triggered.
// Detection has to run on a clock.
//
// The caller runs this inside the LEADER's context (ADR-3/PLAT-2b): every replica correlating would
// multiply materializations, and materialization pages.
//
// A failing tick is counted and logged, never fatal — one bad run must not stop detection for the process
// lifetime.
// PLAT-5b: the interval and BOTH rules are read PER TICK from providers rather than captured at start, so
// a configuration change applies to a running server without a restart. A loop holding the values it was
// constructed with is what makes database-backed configuration a config file with extra steps.
// XDR-4c: `hunts` supplies the configured narrative rules, read PER TICK like everything else here, so
// editing the hunt file applies to a running server. Nil, or an empty slice, means only the breadth
// rule runs — exactly the behaviour before hunts existed.
//
// The breadth rule ALWAYS runs alongside them. A sequence rule is strictly NARROWER than the breadth
// rule it derives from — it only ever adds constraints — so treating hunts as a replacement would lose
// the case they cannot anticipate: three domains lighting up on one asset in a shape nobody wrote a
// rule for, which is the case the breadth rule exists for.
// isLoopStop reports whether an error is this loop's own cancellation rather than a real failure.
//
// BOTH CONDITIONS ARE REQUIRED, and testing the context alone was the bug in the first version.
// `leader.go` cancels the leader context when its Postgres ping fails, so a database outage produces a
// real pgx error AND a cancelled context in the same window; a context-only guard discards the genuine
// failure the metric exists for. Requiring the error to BE the cancellation keeps every other failure —
// schema skew after a migration, a deadlock, pool exhaustion, a malformed operator-authored hunt —
// counted, while still exempting the demotion and shutdown that made this guard necessary.
func isLoopStop(ctx context.Context, err error) bool {
	return ctx.Err() != nil && errors.Is(err, context.Canceled)
}

// NoteTickErr records a failing tick of a scheduled leader loop: it ALWAYS logs, and counts only when the
// error is not this loop's own stop.
//
// EXPORTED ON PURPOSE. The seventh loop that must obey this rule is the retention sweep in
// `cmd/openshield-server`, which is `package main` and cannot see an unexported helper — and that loop is
// the whole reason the guard went repo-wide. A free function rather than a method, because most call
// sites have no receiver to hang it on.
//
// `ctx` is the LOOP'S OWN context and is passed explicitly at every call site, never re-derived here. The
// exemption is keyed on the context the loop was started with, not on the per-tick context handed to the
// work function; those are the same value today (`retain.DynamicLoop` passes `ctx` straight through), and
// a helper that re-derived one from the other would be wrong the moment they diverged. Naming it in the
// argument list is what makes the keying visible at the call site.
//
// WHY THE CONJUNCTION (D485). Exempting on the cancelled context ALONE was the first version of this
// guard, and it was wrong: `leader.go:135-137` cancels `leaderCtx` when its Postgres ping fails, so a
// database outage produces a genuine pgx error AND a cancellation inside the same window. A context-only
// test therefore discards exactly the failure the counter exists to report. Requiring the error to BE the
// cancellation keeps schema skew, deadlocks, pool exhaustion, a malformed operator-authored input and an
// aborted outbound request counted. The error alone is not sufficient either — a cancellation arriving
// while this loop's context is still live belongs to somebody else's abandoned work and is a real fault.
//
// WHY THE LOG IS UNCONDITIONAL (D31). Not counting is about not paging; not RECORDING is a different
// decision, and conflating the two is a defect this project has already shipped once — the first version
// put the log inside the counting branch, so an outage arriving during a shutdown produced no count and
// no line at all. Every failing tick leaves a line, stamped with whether the loop was stopping, so a
// reader can tell an exempted tick from a counted one without inferring it from the counter.
//
// A nil `log` falls back to `slog.Default()` rather than skipping the record: a requirement satisfied
// only by a parameter production never populates is one that ships as a no-op, which is precisely what
// happened here — `cmd/openshield-server` handed every loop a literal `nil` and D485's "logged even when
// not counted" block had never emitted a line from the shipped binary.
//
// NON-LOOP CALLERS INHERIT LOOP SEMANTICS, and should read this before using it. `MaterializeIncidents`
// and `MaterializeCrossDomainIncidents` route their `RecurrenceLinkFailures` writes through here, and
// both are ALSO reached from HTTP handlers carrying `r.Context()`. On that path a client disconnecting
// mid-request cancels the context, so the line is stamped `stopping=true` when nothing is stopping, and
// the increment is skipped — client aborts slightly under-count. The record still exists and is still
// stamped, so no failure goes silent; what is inaccurate is the word, not the presence. Anything reached
// from both a tick and a request should expect that, and a caller that needs the two told apart must
// pass a context that distinguishes them rather than hoping this helper can.
func NoteTickErr(ctx context.Context, log *slog.Logger, msg string, c *atomic.Int64, err error, attrs ...slog.Attr) {
	if log == nil {
		log = slog.Default()
	}
	stopping := isLoopStop(ctx, err)
	// LogAttrs, never log.Error: Error's variadic is `...any`, so slog.Attr values passed to it degrade
	// silently to `!BADKEY` and the `stopping` stamp becomes unreadable.
	//
	// WithoutCancel, because the ONLY lines whose context is dead are the exempted ones. slog passes the
	// context to the handler; TextHandler ignores it, but a buffered, network or OTel-aware handler is
	// entitled to honour a cancelled context by dropping the record — which would silently delete exactly
	// the lines the exemption depends on existing, and leave the counter's absence unexplained. That is
	// the same structural shape as the `if log != nil` bug this change exists to fix: a record that
	// disappears precisely when it is the only evidence.
	log.LogAttrs(context.WithoutCancel(ctx), slog.LevelError, msg,
		append([]slog.Attr{slog.Bool("stopping", stopping), slog.Any("err", err)}, attrs...)...)
	if stopping {
		return
	}
	if c == nil {
		// LOUD, never a silent drop. A nil counter here is a programming error at the call site, and
		// swallowing it would lose a real failure in exactly the way this helper exists to prevent. It
		// does not panic: taking the control plane down from inside a logging helper would be a worse
		// outcome than a loud line, and every current call site passes a real counter.
		log.LogAttrs(context.WithoutCancel(ctx), slog.LevelError,
			"BUG: NoteTickErr was given no counter, so a real failure went uncounted",
			slog.String("uncounted_msg", msg), slog.Any("err", err))
		return
	}
	c.Add(1)
}

func (s *Server) RunCorrelationLoop(ctx context.Context, interval func() time.Duration,
	rules func() (CorrelationRule, CrossDomainRule), hunts func() []CrossDomainRule, log *slog.Logger) {
	// STOPPING IS NOT FAILING — BUT ONLY THE STOP ITSELF IS EXEMPT.
	//
	// A lost leadership (ADR-3) or a process shutdown cancels this loop's context out from under whatever
	// query is in flight. That in-flight call returns "context canceled", and counting it says
	// `openshield_correlation_failures_total` > 0, whose published meaning is "incidents that should have
	// been joined were not, and an attack spanning them reads as unrelated noise". A demoted replica or a
	// clean restart would raise that alarm every time the stop landed mid-tick, and a counter that fires on
	// an ordinary shutdown is one an operator learns to ignore — costing exactly the signal it carries.
	//
	// The decision itself now lives in NoteTickErr — the reasoning above is why it is a conjunction, and
	// its doc comment carries the rest. Every failing branch below routes through it with the LOOP's
	// context (`ctx`), never the per-tick `c`.
	//
	// The tick IS retried: `leader.Run` re-acquires after a demotion and calls onElected again in the same
	// process, so nothing is permanently lost — but that is a reason the exemption is safe, not a reason to
	// widen it.
	retain.DynamicLoop(ctx, interval, func(c context.Context) {
		burst, cross := rules()
		now := s.now()
		if _, err := s.MaterializeIncidents(c, burst, now); err != nil {
			NoteTickErr(ctx, log, "scheduled correlation (burst rule) failed", &CorrelationFailures, err)
		}
		if _, err := s.MaterializeCrossDomainIncidents(c, cross, now); err != nil {
			NoteTickErr(ctx, log, "scheduled correlation (cross-domain rule) failed", &CorrelationFailures, err)
		}
		// XDR-4c: every configured hunt, on the same tick and the same window as the breadth rule
		// unless it says otherwise. A hunt that fails is counted and NAMED, then the next one runs —
		// one unsatisfiable rule must not stop the others, and "correlation failed" without the hunt
		// name is not actionable when several are configured.
		if hunts != nil {
			for _, h := range hunts() {
				if _, err := s.MaterializeCrossDomainIncidents(c, h, now); err != nil {
					// A BROKEN HUNT IS OPERATOR INPUT, and its failure is the only signal that a hunt
					// matches nothing because it is malformed rather than because nothing happened. The
					// hunt NAME travels with the line: "correlation failed" is not actionable when
					// several hunts are configured.
					NoteTickErr(ctx, log, "scheduled correlation (hunt) failed", &CorrelationFailures, err,
						slog.String("hunt", h.Name))
				}
			}
		}
		// XDR-7: recompute cross-domain entity risk on the same tick, so an endpoint detection raises the
		// risk the access proxy applies to that asset's next request — the T2 loop (D89/D91) closed ACROSS
		// domains rather than within peer-UEBA alone.
		if _, err := s.PublishEntityRisk(c, cross.Window, now); err != nil {
			NoteTickErr(ctx, log, "scheduled entity-risk publication failed", &CorrelationFailures, err)
		}
	})
}

// incidentTransitionHandler serves POST /incidents/transition?id=N&to=<state>.
func (s *Server) incidentTransitionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	operator := operatorIdentity(r.Context())
	if operator == "" {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad or missing id", http.StatusBadRequest)
		return
	}
	to := r.URL.Query().Get("to")
	switch err := s.TransitionIncident(r.Context(), id, to, operator); {
	case err == nil:
		writeJSON(w, map[string]any{"id": id, "state": to, "by": operator})
	case errors.Is(err, ErrUnknownState):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, ErrIncidentNotFound):
		http.Error(w, "no such incident", http.StatusNotFound)
	case errors.Is(err, ErrBackwardTransition):
		// 409, not 400: the request is well-formed, it conflicts with the incident's current state.
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, "transition failed", http.StatusInternalServerError)
	}
}
