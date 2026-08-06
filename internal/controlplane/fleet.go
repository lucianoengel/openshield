package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// CONSOLE-8: the fleet roster and the break-glass register.
//
// "'How do I stop this?' is the question a CISO asks before 'what does it detect?'" (INVARIANTS.md:131).
// The product could be stopped fleet-wide and could say nothing about having been: the control's issue
// time, expiry and reason lived only on the wire, and `agent_enforcement` — which records what agents
// report — cannot distinguish an agent disabled by a fleet control from one disabled by its own local
// break-glass file. This file is the other side of that comparison.

// FleetControlRecord is one issued fleet control, together with the four-eyes pair that authorized it.
type FleetControlRecord struct {
	ControlID string    `json:"control_id"`
	Verb      string    `json:"verb"`
	Sequence  uint64    `json:"sequence"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason,omitempty"`
	// Standing is whether this control is the one the fleet is acting on: unexpired, and the highest
	// sequence among unexpired controls. Derived at read time — see FleetSuppression.
	Standing bool `json:"standing"`
	// Requester and Approver are the four-eyes pair, from the approval bound to this control's id.
	// POINTERS, not strings: a RESTORE is not gated and has no approval, and "not applicable" must not
	// serialize the same way as an approval whose requester is somehow blank.
	Requester *string `json:"requester,omitempty"`
	Approver  *string `json:"approver,omitempty"`
	Assurance *string `json:"assurance,omitempty"`
}

// FleetAgent is one enrolled agent as the control plane knows it.
type FleetAgent struct {
	AgentID    string     `json:"agent_id"`
	EnrolledAt time.Time  `json:"enrolled_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	// LastSeen is the newest VERIFIED telemetry (SEC-3: an unsigned publisher must not be able to keep a
	// dead agent looking alive). NIL means never seen — deliberately not the zero time, which would put
	// "silent for 2025 years" in front of an operator and teach them to ignore the field.
	LastSeen  *time.Time     `json:"last_seen"`
	SilentFor *time.Duration `json:"silent_for_ns,omitempty"`
	// EnforcementDisabled is the agent's own report. NIL means it has never acknowledged one — which is
	// NOT "enforcing". An agent that has never reported and one reporting healthy enforcement are
	// different facts, and the second must never be inferred from the first (the same discipline the
	// fleet summary already states about silence).
	EnforcementDisabled *bool      `json:"enforcement_disabled"`
	AppliedSequence     *uint64    `json:"applied_sequence,omitempty"`
	ReportedAt          *time.Time `json:"reported_at,omitempty"`
	// INVENTORY (increment 2), and every one of these is a pointer for the same reason last-seen is: an
	// agent on an older build reports none of them, and "" / 0 would be claims — a version we could not
	// determine, or a spool that is comfortably empty. Absent must be readable as absent.
	Platform     *string `json:"platform,omitempty"`
	AgentVersion *string `json:"agent_version,omitempty"`
	SpoolDepth   *int64  `json:"spool_depth,omitempty"`
}

// FleetRoster is the whole roster plus the fleet-level facts an operator reads it against.
type FleetRoster struct {
	Agents []FleetAgent `json:"agents"`
	// Suppressed is whether a standing fleet control is currently suppressing enforcement.
	Suppressed bool `json:"suppressed"`
	// TargetSequence is the highest control the control plane has issued, so AppliedSequence below it
	// means an agent has not caught up.
	TargetSequence uint64 `json:"target_sequence"`
}

// recordFleetControl writes a control before it is published. See PublishFleetControlSeq for why the
// ordering (after the four-eyes gate, before the wire) is the only defensible one.
func (s *Server) recordFleetControl(ctx context.Context, id string, verb corev1.FleetVerb, seq uint64,
	issued, expires time.Time, reason string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO fleet_controls (control_id, verb, sequence, issued_at, expires_at, reason)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		id, verb.String(), int64(seq), issued, expires, reason)
	if err != nil {
		return fmt.Errorf("controlplane: recording fleet control %s: %w", id, err)
	}
	return nil
}

// FleetControls returns the break-glass register, newest control first, with each control's four-eyes
// pair and whether it is the one standing as of now.
//
// The pair is JOINED rather than copied at publish time. Publication runs from an operator-local command
// (D51) with no authenticated principal in scope, so an `issued_by` written there would name an identity
// nothing verified — the failure migration 046 exists to avoid. The approval IS the verified identity.
func (s *Server) FleetControls(ctx context.Context, now time.Time, limit int) ([]FleetControlRecord, error) {
	if limit <= 0 || limit > maxSearchLimit {
		limit = maxSearchLimit
	}
	rows, err := s.pool.Query(ctx,
		`SELECT fc.control_id, fc.verb, fc.sequence, fc.issued_at, fc.expires_at, fc.reason,
		        a.requester, a.approver, a.assurance
		   FROM fleet_controls fc
		   LEFT JOIN approvals a
		          ON a.subject_kind = $1 AND a.subject_id = fc.control_id
		  ORDER BY fc.sequence DESC
		  LIMIT $2`, ApprovalSubjectFleetControl, limit)
	if err != nil {
		return nil, fmt.Errorf("controlplane: reading fleet controls: %w", err)
	}
	defer rows.Close()

	var out []FleetControlRecord
	for rows.Next() {
		var r FleetControlRecord
		var seq int64
		if err := rows.Scan(&r.ControlID, &r.Verb, &seq, &r.IssuedAt, &r.ExpiresAt, &r.Reason,
			&r.Requester, &r.Approver, &r.Assurance); err != nil {
			return nil, fmt.Errorf("controlplane: reading fleet controls: %w", err)
		}
		r.Sequence = uint64(seq)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("controlplane: reading fleet controls: %w", err)
	}
	// STANDING IS DERIVED, and only one control can hold it: the highest-sequence unexpired one. Rows are
	// already ordered by sequence descending, so the first unexpired row is it.
	for i := range out {
		if now.Before(out[i].ExpiresAt) {
			out[i].Standing = true
			break
		}
	}
	return out, nil
}

// FleetSuppression answers whether enforcement is currently suppressed fleet-wide.
//
// DERIVED, NEVER STORED, and computed exactly as a consumer computes it (intent/fleetcontrol.go): the
// highest-SEQUENCE control whose expiry has not lapsed, suppression holding if that control is a disable.
//
// Ordering is by sequence and not by issued_at because sequence is what consumers order by; ordering the
// operator surface by wall-clock time while agents order by sequence would let the two disagree under
// clock skew, which is a console that reports protection the fleet does not have.
//
// A stored boolean would need a sweeper to end suppression when a TTL lapses, and a sweeper that falls
// behind lies in the direction that matters.
func (s *Server) FleetSuppression(ctx context.Context, now time.Time) (bool, error) {
	var verb string
	err := s.pool.QueryRow(ctx,
		`SELECT verb FROM fleet_controls WHERE expires_at > $1 ORDER BY sequence DESC LIMIT 1`, now).
		Scan(&verb)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil // no control stands; the fleet enforces
		}
		return false, fmt.Errorf("controlplane: deriving fleet suppression: %w", err)
	}
	return verb == corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE.String(), nil
}

// Fleet returns the roster: every enrolled agent, its liveness from verified telemetry, and its
// self-reported enforcement state.
//
// The roster is authoritative (agent_identities LEFT JOIN the rest), so an enrolled agent that has never
// sent anything still appears — with both facts absent rather than defaulted. An agent that vanishes from
// a surface is one nobody investigates.
func (s *Server) Fleet(ctx context.Context, now time.Time) (FleetRoster, error) {
	roster := FleetRoster{Agents: []FleetAgent{}}

	rows, err := s.pool.Query(ctx,
		`SELECT ai.agent_id, ai.enrolled_at, ai.revoked_at,
		        (SELECT max(ft.received_at) FROM fleet_telemetry ft
		          WHERE ft.agent_id = ai.agent_id AND ft.verified = true),
		        ae.disabled, ae.applied_sequence, ae.reported_at,
		        ae.platform, ae.agent_version, ae.spool_depth
		   FROM agent_identities ai
		   LEFT JOIN agent_enforcement ae ON ae.agent_id = ai.agent_id
		  ORDER BY ai.agent_id`)
	if err != nil {
		return roster, fmt.Errorf("controlplane: reading the fleet roster: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var a FleetAgent
		var applied *int64
		if err := rows.Scan(&a.AgentID, &a.EnrolledAt, &a.RevokedAt, &a.LastSeen,
			&a.EnforcementDisabled, &applied, &a.ReportedAt,
			&a.Platform, &a.AgentVersion, &a.SpoolDepth); err != nil {
			return roster, fmt.Errorf("controlplane: reading the fleet roster: %w", err)
		}
		if applied != nil {
			seq := uint64(*applied)
			a.AppliedSequence = &seq
		}
		if a.LastSeen != nil {
			d := now.Sub(*a.LastSeen)
			a.SilentFor = &d
		}
		roster.Agents = append(roster.Agents, a)
	}
	if err := rows.Err(); err != nil {
		return roster, fmt.Errorf("controlplane: reading the fleet roster: %w", err)
	}

	if roster.Suppressed, err = s.FleetSuppression(ctx, now); err != nil {
		return roster, err
	}
	roster.TargetSequence = s.CurrentFleetSequence(ctx)
	return roster, nil
}

// parseFleetLimit reads the register's `limit`, refusing a malformed one rather than silently falling
// back to the default (SEC-8), and clamping a large ask rather than erroring on it.
func parseFleetLimit(r *http.Request) (int, error) {
	v := strings.TrimSpace(r.URL.Query().Get("limit"))
	if v == "" {
		return 100, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("limit %q is not a positive integer", v)
	}
	if n > maxSearchLimit {
		n = maxSearchLimit
	}
	return n, nil
}

// fleetHandler serves GET /fleet — the roster.
func (s *Server) fleetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	roster, err := s.Fleet(r.Context(), s.now())
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, roster)
}

// fleetControlsHandler serves GET /fleet/controls — the break-glass register.
func (s *Server) fleetControlsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit, err := parseFleetLimit(r)
	if err != nil {
		// SEC-8: a malformed limit is a 400, not a silent fall-back to the default.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	now := s.now()
	controls, err := s.FleetControls(r.Context(), now, limit)
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	suppressed, err := s.FleetSuppression(r.Context(), now)
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	if controls == nil {
		controls = []FleetControlRecord{} // never `null`: an empty register and an unreadable one must not look alike
	}
	writeJSON(w, struct {
		Suppressed bool                 `json:"suppressed"`
		Controls   []FleetControlRecord `json:"controls"`
	}{Suppressed: suppressed, Controls: controls})
}
