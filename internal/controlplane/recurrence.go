package controlplane

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// INCIDENT RECURRENCE (SOAR-2b).
//
// The lifecycle stays forward-only — see soar2.go for why, and that reasoning has not changed. What
// this adds is the thing the forward-only rule was silently costing: when the same trouble comes back
// after an incident was closed, the new incident is LINKED to the one it recurs from, and carries how
// many times it has now returned.
//
// The distinction matters because the two readings are opposite. A first-occurrence incident asks "what
// is this?"; the fourth recurrence in a week asks "why does closing this not make it stop?" — and until
// now both arrived on the pager looking identical. A recurrence is the strongest available evidence that
// a previous close was premature, and that evidence was being discarded at exactly the moment it was
// produced.
//
// WHAT THIS DELIBERATELY IS NOT: it is not a `closed → open` transition, and adding one is still
// refused. TransitionIncident's contract is unchanged, MTTA/MTTR still read a monotone timeline, and no
// stored timestamp is ever rewritten. The chain is metadata ABOUT a sequence of incidents, not a way to
// resurrect one.

// RecurrenceLinkFailures counts incidents that were raised but could not be linked to their predecessor.
//
// It is separate from CorrelationFailures on purpose: the incident itself is fine and an operator will
// see it. What is missing is only the knowledge that it has happened before — a quieter failure, and one
// that makes the product look calmer than it is.
var RecurrenceLinkFailures atomic.Int64

// DefaultRecurrenceWindow bounds how far back a predecessor may be and still count as a recurrence.
//
// A bound is required, not a nicety. Without one, the very first incident a long-lived subject ever had
// becomes the ancestor of every incident it has years later, and "recurrence #37" degrades into "this
// subject has existed for a while" — a number that looks like a finding and is not one.
const DefaultRecurrenceWindow = 7 * 24 * time.Hour

// Recurrence describes an incident's relationship to its predecessor. The zero value means "first
// occurrence", which is what most incidents are.
type Recurrence struct {
	// Of is the incident this one recurs from; 0 when there is none.
	Of int64 `json:"recurrence_of,omitempty"`
	// Count is how many times this trouble has now returned (0 = first occurrence).
	Count int `json:"recurrence_count"`
	// Since is how long after the predecessor's last activity this one appeared. Reported because
	// "came back in 20 minutes" and "came back in 5 days" warrant different responses, and the
	// notification is where an operator sees it.
	Since time.Duration `json:"-"`
}

// linkRecurrence points a freshly inserted incident at its predecessor, if it has one inside the window.
//
// Called ONLY on a genuine insert (the materializers' `xmax = 0` path). Running it on the DO UPDATE path
// would relink a still-open incident to older history on every correlation tick, inflating the count
// with re-correlations of one ongoing event — the opposite of what the number claims to mean.
//
// The predecessor is constrained to `id < newID` so a chain is strictly decreasing and therefore acyclic
// by construction, which matters because the walk in RecurrenceChain is recursive SQL and a cycle there
// is a query that never returns. Stated honestly: that clause is currently redundant — a freshly
// inserted incident is always `open`, so `state <> 'open'` already excludes it, and no mutation of the
// id clause alone changes an outcome today. It is kept because the acyclicity it guarantees is a
// property of the chain, not of who happens to call this.
//
// A failure here is returned to the caller, which logs it and carries on: the incident row is the
// record, the link is an annotation on it, and losing an annotation must not lose the incident.
func (s *Server) linkRecurrence(ctx context.Context, newID int64, kind, subjectID string,
	entityID *int64, window time.Duration, now time.Time) (Recurrence, error) {
	if window <= 0 {
		window = DefaultRecurrenceWindow
	}
	cutoff := now.Add(-window)

	var rec Recurrence
	var prevLastSeen time.Time
	// The predecessor match is by subject for the burst rule and by entity for the cross-domain rule —
	// the same keys their open-incident uniqueness indexes use, because "the same trouble" has to mean
	// the same thing to both mechanisms or a recurrence and a re-open would disagree about identity.
	err := s.pool.QueryRow(ctx,
		`WITH prev AS (
		   SELECT id, recurrence_count, last_seen
		     FROM incidents
		    WHERE kind = $2
		      AND state <> 'open'
		      AND id < $1
		      AND CASE WHEN $2 = 'cross_domain' THEN entity_id IS NOT DISTINCT FROM $4::bigint
		               ELSE subject_id = $3 END
		      AND last_seen >= $5
		    ORDER BY id DESC
		    LIMIT 1
		 )
		 UPDATE incidents
		    SET recurrence_of = prev.id, recurrence_count = prev.recurrence_count + 1, updated_at = now()
		   FROM prev
		  WHERE incidents.id = $1
		 RETURNING incidents.recurrence_of, incidents.recurrence_count, prev.last_seen`,
		newID, kind, subjectID, entityID, cutoff).
		Scan(&rec.Of, &rec.Count, &prevLastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return Recurrence{}, nil // first occurrence, or the last one is older than the window
	}
	if err != nil {
		return Recurrence{}, err
	}
	rec.Since = now.Sub(prevLastSeen)
	return rec, nil
}

// RecurrenceChain returns every incident in one recurrence chain, oldest first, given any member of it.
//
// Given ANY member, not just the newest: an operator who arrives from a case, a ticket or an old
// notification is holding whichever id that artefact recorded, and a chain reachable only from its head
// would be unreachable from exactly the places people actually enter it. So the walk goes up to the
// root and then back down, and the answer does not depend on where you got in.
//
// An incident with no predecessor and no successor comes back as a chain of one, not an error — "this
// has happened once" is a real answer to the question, and an empty result would read as "no such
// incident" when the incident is right there.
func (s *Server) RecurrenceChain(ctx context.Context, id int64) ([]StoredIncident, error) {
	rows, err := s.pool.Query(ctx,
		`WITH RECURSIVE up AS (
		     SELECT id, recurrence_of FROM incidents WHERE id = $1
		   UNION ALL
		     SELECT i.id, i.recurrence_of FROM incidents i JOIN up ON i.id = up.recurrence_of
		 ), root AS (
		   SELECT id FROM up WHERE recurrence_of IS NULL LIMIT 1
		 ), chain AS (
		     SELECT id FROM root
		   UNION ALL
		     SELECT i.id FROM incidents i JOIN chain ON i.recurrence_of = chain.id
		 )
		 SELECT i.id, i.subject_id, i.state, i.alert_count, i.max_risk, i.host_count,
		        i.first_seen, i.last_seen, i.acknowledged_by, i.acknowledged_at,
		        COALESCE(i.recurrence_of, 0), i.recurrence_count
		   FROM incidents i JOIN chain ON i.id = chain.id
		  ORDER BY i.id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredIncident
	for rows.Next() {
		var i StoredIncident
		if err := rows.Scan(&i.ID, &i.SubjectID, &i.State, &i.AlertCount, &i.MaxRisk, &i.HostCount,
			&i.FirstSeen, &i.LastSeen, &i.AcknowledgedBy, &i.AcknowledgedAt,
			&i.RecurrenceOf, &i.RecurrenceCount); err != nil {
			return nil, err
		}
		i.Severity = Severity(i.MaxRisk)
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrIncidentNotFound
	}
	return out, nil
}

// incidentRecurrencesHandler serves GET /incidents/recurrences?id=N.
func (s *Server) incidentRecurrencesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad or missing id", http.StatusBadRequest)
		return
	}
	chain, err := s.RecurrenceChain(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrIncidentNotFound) {
			http.Error(w, "no such incident", http.StatusNotFound)
			return
		}
		http.Error(w, "recurrence lookup failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"id": id, "occurrences": len(chain), "chain": chain})
}
