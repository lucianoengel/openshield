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
	tag, err := s.pool.Exec(ctx,
		`UPDATE incidents SET state = $1, transitioned_by = $2, transitioned_at = now(), updated_at = now()
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
func (s *Server) RunCorrelationLoop(ctx context.Context, interval time.Duration,
	burst CorrelationRule, cross CrossDomainRule, log *slog.Logger) {
	retain.Loop(ctx, interval, func(c context.Context) {
		now := s.now()
		if _, err := s.MaterializeIncidents(c, burst, now); err != nil {
			CorrelationFailures.Add(1)
			if log != nil {
				log.Error("scheduled correlation (burst rule) failed", slog.Any("err", err))
			}
		}
		if _, err := s.MaterializeCrossDomainIncidents(c, cross, now); err != nil {
			CorrelationFailures.Add(1)
			if log != nil {
				log.Error("scheduled correlation (cross-domain rule) failed", slog.Any("err", err))
			}
		}
		// XDR-7: recompute cross-domain entity risk on the same tick, so an endpoint detection raises the
		// risk the access proxy applies to that asset's next request — the T2 loop (D89/D91) closed ACROSS
		// domains rather than within peer-UEBA alone.
		if _, err := s.PublishEntityRisk(c, cross.Window, now); err != nil {
			CorrelationFailures.Add(1)
			if log != nil {
				log.Error("scheduled entity-risk publication failed", slog.Any("err", err))
			}
		}
	})
}

// incidentTransitionHandler serves POST /incidents/transition?id=N&to=<state>.
func (s *Server) incidentTransitionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	operator := operatorIdentity(r.TLS)
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
