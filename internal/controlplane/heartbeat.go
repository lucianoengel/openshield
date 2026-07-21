package controlplane

import (
	"context"
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
	if err := s.insert(ctx, "heartbeat", h.GetAgentId(), "", data); err != nil {
		s.DecodeFailures.Add(1)
	}
}

// LastSeen returns when the control plane last heard from an agent — via any
// telemetry OR a heartbeat. Zero time and ok=false if the agent is unknown.
func (s *Server) LastSeen(ctx context.Context, agentID string) (time.Time, bool, error) {
	var t time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT max(received_at) FROM fleet_telemetry WHERE agent_id = $1`, agentID).Scan(&t)
	if err != nil {
		// No rows → the aggregate returns a NULL max, which scans as an error
		// only if we required non-null. Treat "no such agent" as not-found.
		return time.Time{}, false, nil
	}
	if t.IsZero() {
		return time.Time{}, false, nil
	}
	return t, true, nil
}

// Overdue reports agents silent longer than threshold as of now. It reads each
// known agent's last-seen and applies the pure detector.
func (s *Server) Overdue(ctx context.Context, threshold time.Duration, now time.Time) ([]AgentStatus, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT agent_id, max(received_at) FROM fleet_telemetry
		 WHERE agent_id <> '' GROUP BY agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var statuses []AgentStatus
	for rows.Next() {
		var st AgentStatus
		if err := rows.Scan(&st.AgentID, &st.LastSeen); err != nil {
			return nil, err
		}
		statuses = append(statuses, st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return OverdueAgents(statuses, threshold, now), nil
}
