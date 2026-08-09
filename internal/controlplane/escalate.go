package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/lucianoengel/openshield/internal/notify"
	"github.com/lucianoengel/openshield/internal/retain"
)

// ESCALATION LADDERS (SOAR-9b).
//
// SOAR-9 decided WHERE a notification goes at the moment it is raised. Nothing decided what happens when
// it goes there and nobody answers — and that is the failure alerting systems actually die of. The page
// is delivered, delivery is recorded as a success, and the incident sits open until someone happens to
// look at a queue. Every part of the machine reports that it worked.
//
// A ladder is a list of rungs: after this long unacknowledged, notify these sinks. It is a TIMER, not a
// schedule — see the deferral note on Ladder.
//
// THE RUNG IS A SEPARATE NOTIFICATION KIND, not a re-send of the original. Routing keys on kind, so a
// re-send would go exactly where the ignored page went; escalating means reaching somewhere else, and
// KindEscalation is what makes that expressible in the routing table an operator already writes.
//
// ACKNOWLEDGEMENT STOPS THE LADDER, and that is the whole mechanism. The sweep selects incidents still in
// `open`; the first transition off it — which every path stamps acknowledged_at through — takes the
// incident out of scope permanently. There is no "cancel" step to forget to call.

// EscalationsSent counts rungs fired. EscalationFailures counts sweeps that errored: a ladder that has
// silently stopped climbing looks identical, from the outside, to a fleet where everything is being
// acknowledged promptly — which is the flattering reading, and the wrong one.
var (
	EscalationsSent    atomic.Int64
	EscalationFailures atomic.Int64
)

// Rung is one step of a ladder.
type Rung struct {
	// After is how long an incident may stay unacknowledged before this rung fires, measured from when
	// the incident was RAISED, not from the previous rung. Measuring from the previous rung would make
	// the deadlines depend on when the sweep happened to run.
	After time.Duration `json:"-"`
	// AfterSeconds is the wire form of After, so a ladder is expressible in the JSON configuration
	// operators already use for routing tables.
	AfterSeconds int `json:"after_seconds"`
	// MinSeverity limits this rung to incidents at or above a severity. Empty = any severity.
	MinSeverity string `json:"min_severity,omitempty"`
	// Sinks names where this rung goes. A rung with no sinks is refused at load, for the same reason a
	// routing rule with no sinks is: it would silently discard exactly what it matched.
	Sinks []string `json:"sinks"`
}

// Ladder is the ordered set of rungs.
//
// DELIBERATELY NOT A SCHEDULE. There is no time-of-day, no rotation, no calendar and no "who is on call
// this week" — those need an on-call roster this product does not have and should not invent, and a
// half-built rotation that silently pages the wrong person is worse than none. What is here is the timer
// half, which is what the capability table named as missing. The roster half stays named as absent.
type Ladder struct {
	Rungs []Rung `json:"rungs"`
}

// ErrBadLadder is a structurally invalid ladder.
var ErrBadLadder = errors.New("controlplane: invalid escalation ladder")

// LoadLadder parses and VALIDATES a ladder against the configured sink names.
//
// Validated at LOAD, like routing tables, because an escalation mistake discovered at firing time is
// discovered by a page that did not arrive — which is the thing this exists to prevent.
func LoadLadder(r io.Reader, sinkNames []string) (Ladder, error) {
	var l Ladder
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return Ladder{}, fmt.Errorf("%w: %v", ErrBadLadder, err)
	}
	known := make(map[string]bool, len(sinkNames))
	for _, s := range sinkNames {
		known[s] = true
	}
	prev := -1
	for i := range l.Rungs {
		r := &l.Rungs[i]
		if r.AfterSeconds <= 0 {
			return Ladder{}, fmt.Errorf("%w: rung %d has no deadline", ErrBadLadder, i)
		}
		// STRICTLY INCREASING, refused rather than sorted. A ladder whose second rung fires before its
		// first is a typo, and quietly reordering it would deliver a working ladder that is not the one
		// the operator wrote — the failure they would then never find.
		if r.AfterSeconds <= prev {
			return Ladder{}, fmt.Errorf("%w: rung %d fires at %ds, not after the previous rung's %ds",
				ErrBadLadder, i, r.AfterSeconds, prev)
		}
		prev = r.AfterSeconds
		r.After = time.Duration(r.AfterSeconds) * time.Second
		if len(r.Sinks) == 0 {
			return Ladder{}, fmt.Errorf("%w: rung %d selects no sinks", ErrBadLadder, i)
		}
		if r.MinSeverity != "" {
			if _, ok := notify.SeverityRank(r.MinSeverity); !ok {
				return Ladder{}, fmt.Errorf("%w: rung %d: %q is not a severity", ErrBadLadder, i, r.MinSeverity)
			}
		}
		for _, s := range r.Sinks {
			if !known[s] {
				return Ladder{}, fmt.Errorf("%w: rung %d names sink %q, which is not configured",
					ErrBadLadder, i, s)
			}
		}
	}
	return l, nil
}

// overdueIncident is one candidate for escalation.
type overdueIncident struct {
	id       int64
	subject  string
	severity string
	risk     float64
	raisedAt time.Time
}

// Escalate fires every rung whose deadline has passed on every still-unacknowledged incident, exactly
// once each. Returns how many rungs fired.
//
// The `open` filter is the acknowledgement check: an operator who acknowledges, triages, contains or
// closes moves the incident off `open`, and it leaves the candidate set for good.
func (s *Server) Escalate(ctx context.Context, l Ladder, now time.Time) (int, error) {
	if len(l.Rungs) == 0 {
		return 0, nil
	}
	// The widest deadline bounds the scan: an incident younger than the first rung cannot escalate.
	earliest := l.Rungs[0].After
	rows, err := s.pool.Query(ctx,
		`SELECT id, subject_id, max_risk, created_at
		   FROM incidents
		  WHERE state = 'open' AND created_at <= $1
		  ORDER BY id`, now.Add(-earliest))
	if err != nil {
		return 0, err
	}
	var candidates []overdueIncident
	for rows.Next() {
		var c overdueIncident
		if err := rows.Scan(&c.id, &c.subject, &c.risk, &c.raisedAt); err != nil {
			rows.Close()
			return 0, err
		}
		c.severity = Severity(c.risk)
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	fired := 0
	for _, c := range candidates {
		age := now.Sub(c.raisedAt)
		for i, rung := range l.Rungs {
			if age < rung.After {
				break // rungs are strictly increasing, so no later one is due either
			}
			if rung.MinSeverity != "" {
				floor, _ := notify.SeverityRank(rung.MinSeverity)
				got, ok := notify.SeverityRank(c.severity)
				if !ok || got < floor {
					continue
				}
			}
			// CLAIM THE RUNG BEFORE SENDING. The insert is the lock: ON CONFLICT DO NOTHING means a
			// second sweep — a concurrent one, or the same one after a restart — inserts no row and
			// sends nothing. Sending first and recording after would re-page on any crash in between,
			// and the crash window is exactly when an operator is least able to absorb a duplicate.
			tag, err := s.pool.Exec(ctx,
				`INSERT INTO incident_escalations (incident_id, rung, after_secs, sinks, escalated_at)
				 VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
				c.id, i, rung.AfterSeconds, rung.Sinks, now)
			if err != nil {
				return fired, err
			}
			if tag.RowsAffected() == 0 {
				continue // already climbed
			}
			s.emit(ctx, notify.Notification{
				Kind:      notify.KindEscalation,
				Subject:   c.subject,
				RiskScore: c.risk,
				Severity:  c.severity,
				At:        now,
				// Namespaced per incident AND per rung, so a receiver deduping on ID does not treat the
				// second rung as a retry of the first and swallow the escalation.
				ID: fmt.Sprintf("esc_%d_%d", c.id, i),
				Detail: fmt.Sprintf("ESCALATION: incident %d (%s) has been unacknowledged for %s",
					c.id, c.severity, age.Round(time.Minute)),
			})
			EscalationsSent.Add(1)
			fired++
		}
	}
	return fired, nil
}

// RunEscalationLoop sweeps for overdue incidents on an interval.
//
// LEADER-ONLY, like the correlation loop: every replica sweeping would multiply pages, and the durable
// rung claim would only turn that into a race the loser of which merely stays silent. The ladder is read
// PER TICK so a change applies without a restart (PLAT-5b).
//
// A failing sweep is counted and logged, never fatal — one bad tick must not stop escalation for the
// process lifetime, which would leave the ladder silently disabled in exactly the way it exists to
// prevent.
func (s *Server) RunEscalationLoop(ctx context.Context, interval func() time.Duration,
	ladder func() Ladder, log *slog.Logger) {
	retain.DynamicLoop(ctx, interval, func(c context.Context) {
		if _, err := s.Escalate(c, ladder(), s.now()); err != nil {
			NoteTickErr(ctx, log, "incident escalation sweep failed", &EscalationFailures, err)
		}
	})
}
