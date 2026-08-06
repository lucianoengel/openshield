package controlplane

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// AgentStatus is one agent's liveness as the control plane sees it.
type AgentStatus struct {
	AgentID  string
	LastSeen time.Time
	// Overdue is set by the dead-man's-switch when LastSeen is older than the
	// threshold. Overdue is a SIGNAL for a human to investigate, not proof of
	// tampering — a laptop legitimately sleeps and travels (D16).
	Overdue bool
	// Silence is how long the agent has been quiet as of the evaluation time.
	Silence time.Duration
}

// OverdueAgents is the dead-man's-switch, as a PURE function of last-seen times
// and a threshold. It is pure precisely because the logic that decides "someone
// should look" must be trivially verifiable — no database, no clock beyond the
// `now` passed in. An agent is overdue when it has been silent longer than the
// threshold.
//
// The threshold should be several heartbeat intervals so normal jitter and brief
// offline periods (which the offline queue heals on reconnect, T-024) do not cry
// wolf.
func OverdueAgents(statuses []AgentStatus, threshold time.Duration, now time.Time) []AgentStatus {
	var overdue []AgentStatus
	for _, s := range statuses {
		s.Silence = now.Sub(s.LastSeen)
		if s.Silence > threshold {
			s.Overdue = true
			overdue = append(overdue, s)
		}
	}
	return overdue
}

// recordHeartbeat stores a heartbeat as a telemetry row so last-seen advances
// uniformly whether an agent reported real telemetry or only checked in.
func (s *Server) recordHeartbeat(ctx context.Context, data []byte) {
	var h corev1.Heartbeat
	if err := proto.Unmarshal(data, &h); err != nil {
		s.DecodeFailures.Add(1)
		return
	}
	if err := s.insert(ctx, "heartbeat", h.GetAgentId(), "", data, false); err != nil {
		s.DecodeFailures.Add(1)
	}
	s.recordEnforcementState(ctx, &h)
}

// recordEnforcementState projects the heartbeat's enforcement acknowledgement (PLAT-9), so "did my fleet
// disable arrive?" is an indexed query rather than a scan of heartbeat payloads.
//
// Best-effort and never fatal: the heartbeat's own purpose is last-seen, and a projection failure must not
// cost the fleet its liveness signal. The write is a plain upsert — the LATEST report wins, because an
// agent's current state is what an operator is asking about.
func (s *Server) recordEnforcementState(ctx context.Context, h *corev1.Heartbeat) {
	if h.GetAgentId() == "" {
		return
	}
	// CONSOLE-8: the inventory rides the same upsert. An agent on an older build sends none of these
	// fields, and proto3 would give us "" and 0 — both of which are CLAIMS ("" reads as a version we
	// could not determine, 0 as an empty spool). So an absent field is stored as NULL rather than as its
	// zero value, and the roster reports it absent.
	var platform, version *string
	var spool *int64
	if p := h.GetPlatform(); p != "" {
		platform = &p
	}
	if v := h.GetAgentVersion(); v != "" {
		version = &v
	}
	// Spool depth has no distinguishable zero on the wire, so it is stored only when the agent
	// identified itself at all — an agent old enough to omit the platform is old enough to have no
	// spool depth to report, and a hard 0 from it would look like a healthy empty queue.
	if platform != nil || version != nil {
		d := int64(h.GetSpoolDepth())
		spool = &d
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO agent_enforcement (agent_id, disabled, applied_sequence, reported_at,
		                                platform, agent_version, spool_depth)
		 VALUES ($1,$2,$3, now(), $4,$5,$6)
		 ON CONFLICT (agent_id) DO UPDATE SET disabled = EXCLUDED.disabled,
		     applied_sequence = EXCLUDED.applied_sequence, reported_at = now(),
		     platform = EXCLUDED.platform, agent_version = EXCLUDED.agent_version,
		     spool_depth = EXCLUDED.spool_depth`,
		h.GetAgentId(), h.GetEnforcementDisabled(), int64(h.GetAppliedFleetSequence()),
		platform, version, spool); err != nil {
		s.DecodeFailures.Add(1)
	}
}

// FleetEnforcement summarizes what the fleet is actually doing.
type FleetEnforcement struct {
	Agents         int    `json:"agents"`
	Disabled       int    `json:"disabled"`
	Enforcing      int    `json:"enforcing"`
	NotCaughtUp    int    `json:"not_caught_up"`
	TargetSequence uint64 `json:"target_sequence"`
}

// FleetEnforcementState answers the two questions an operator has after issuing a fleet-wide disable:
// which hosts are still ENFORCING, and which have not yet CAUGHT UP to the latest control.
//
// THE HONEST LIMIT, and it matters: this reports only what agents have TOLD us. A silent agent contributes
// nothing, so "no news" is NOT "still enforcing" — an agent that is gone looks exactly like one that has
// not checked in. Absence is the overdue mechanism's job (D50/D51), and this must not be read as covering
// it.
func (s *Server) FleetEnforcementState(ctx context.Context, target uint64) (FleetEnforcement, error) {
	var f FleetEnforcement
	f.TargetSequence = target
	err := s.pool.QueryRow(ctx,
		`SELECT count(*), count(*) FILTER (WHERE disabled), count(*) FILTER (WHERE NOT disabled),
		        count(*) FILTER (WHERE applied_sequence < $1)
		   FROM agent_enforcement`, int64(target)).
		Scan(&f.Agents, &f.Disabled, &f.Enforcing, &f.NotCaughtUp)
	return f, err
}

// LastSeen returns when the control plane last heard from an agent — via any
// telemetry OR a heartbeat. Zero time and ok=false if the agent is unknown.
func (s *Server) LastSeen(ctx context.Context, agentID string) (time.Time, bool, error) {
	// SEC-3: count only VERIFIED telemetry — an unsigned publisher must not be able to
	// refresh an agent's last-seen. SEC-11: distinguish a DB ERROR from AGENT ABSENCE — a
	// down database must surface as an error, not masquerade as "agent unknown" (which
	// would silently hide the whole fleet). max() over no rows returns a NULL, scanned into
	// a *time.Time (nil = never seen); a real query error is returned as an error.
	var t *time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT max(received_at) FROM fleet_telemetry WHERE agent_id = $1 AND verified = true`,
		agentID).Scan(&t)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("controlplane: LastSeen(%s): %w", agentID, err)
	}
	if t == nil || t.IsZero() {
		return time.Time{}, false, nil // genuinely no verified telemetry for this agent
	}
	return *t, true, nil
}

// Overdue reports agents silent longer than threshold as of now. It reads each
// known agent's last-seen and applies the pure detector.
func (s *Server) Overdue(ctx context.Context, threshold time.Duration, now time.Time) ([]AgentStatus, error) {
	// SEC-3: liveness derives from the ROSTER (enrolled, non-revoked agents) LEFT JOINed to
	// their last VERIFIED telemetry. Two fixes over the old `max(received_at) FROM
	// fleet_telemetry`: (1) only verified rows count, so an unsigned publisher cannot keep a
	// dead/compromised agent "alive"; (2) the roster is authoritative, so an enrolled-but-
	// silent agent (never sent, or purged) still surfaces as overdue instead of vanishing.
	rows, err := s.pool.Query(ctx,
		`SELECT ai.agent_id, max(ft.received_at)
		   FROM agent_identities ai
		   LEFT JOIN fleet_telemetry ft
		     ON ft.agent_id = ai.agent_id AND ft.verified = true
		  WHERE ai.revoked_at IS NULL
		  GROUP BY ai.agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var statuses []AgentStatus
	for rows.Next() {
		var st AgentStatus
		var last *time.Time // NULL when the agent has no verified telemetry (never seen)
		if err := rows.Scan(&st.AgentID, &last); err != nil {
			return nil, err
		}
		if last != nil {
			st.LastSeen = *last
		}
		// A never-seen agent has zero LastSeen → maximally overdue, which is correct.
		statuses = append(statuses, st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return OverdueAgents(statuses, threshold, now), nil
}

// CurrentFleetSequence is the highest fleet-control sequence this control plane has published — the
// TARGET agents are measured against. Zero when none has ever been published, in which case no agent can
// be behind.
func (s *Server) CurrentFleetSequence(ctx context.Context) uint64 {
	if s.pool == nil {
		return 0
	}
	var seq uint64
	if err := s.pool.QueryRow(ctx,
		`SELECT coalesce((SELECT value::bigint FROM config_settings WHERE key='__fleet_control_sequence'),0)`).
		Scan(&seq); err != nil {
		return 0
	}
	return seq
}

// fleetEnforcementMetrics renders the fleet's enforcement state for the Prometheus endpoint.
//
// This is the operator surface the acknowledgement exists for: during an incident the question is "how
// many are still enforcing?", and a gauge answers it for the deployment where a log line answers it per
// host.
//
// NOTE ON WHAT THE NUMBERS MEAN, because a gauge invites the wrong reading: these count agents that have
// REPORTED. A silent agent contributes to none of them — "no news" is not "still enforcing", and absence
// is the overdue metric's job, not this one.
func (s *Server) fleetEnforcementMetrics(ctx context.Context) (string, error) {
	if s.pool == nil {
		// The counters half of /metrics needs no database and must keep serving without one — the same
		// rule the response histograms follow, and the reason the gate caught this.
		return "", errors.New("controlplane: fleet enforcement state needs a database")
	}
	target := s.CurrentFleetSequence(ctx)
	f, err := s.FleetEnforcementState(ctx, target)
	if err != nil {
		return "", err
	}
	out := ""
	for _, m := range []struct {
		name, help string
		val        int
	}{
		{"openshield_fleet_agents_reporting", "Agents that have reported an enforcement state. A silent agent counts in NONE of these — absence is openshield_agents_overdue's job.", f.Agents},
		{"openshield_fleet_agents_enforcing", "Reporting agents whose enforcement is ACTIVE.", f.Enforcing},
		{"openshield_fleet_agents_disabled", "Reporting agents whose enforcement is DISABLED — by a fleet control or by a local break-glass file.", f.Disabled},
		{"openshield_fleet_agents_behind", "Reporting agents that have not applied the current fleet control.", f.NotCaughtUp},
	} {
		out += fmt.Sprintf("# HELP %s %s\n# TYPE %s gauge\n%s %d\n", m.name, m.help, m.name, m.name, m.val)
	}
	out += fmt.Sprintf("# HELP openshield_fleet_control_sequence The highest fleet-control sequence published.\n"+
		"# TYPE openshield_fleet_control_sequence gauge\nopenshield_fleet_control_sequence %d\n", target)
	return out, nil
}
