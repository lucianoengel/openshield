// Package controlplane is the server side of OpenShield (T-023).
//
// It subscribes to the agent telemetry subjects and persists what it receives to
// a FLEET AGGREGATE store. This is deliberately NOT the agent's forward-secure
// audit ledger (D12/D30): the aggregate has no hash chain and no signatures, a
// compromised control plane could alter it, and the evidentiary record lives at
// the agent, externally anchored (T-019). The aggregate is a queryable
// convenience — "what did the fleet see" — and must never be presented as
// evidence.
//
// It coordinates and observes; it does NOT distribute policy or control agents
// (D14 — "the server coordinates, it does not control"). NATS lives here, never
// in core (D24).
package controlplane

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// TelemetryRow is one persisted aggregate record.
type TelemetryRow struct {
	AgentID    string
	Kind       string
	EventID    string
	ReceivedAt time.Time
	Payload    []byte
}

// Server receives and persists agent telemetry.
type Server struct {
	pool *pgxpool.Pool

	mu   sync.Mutex
	subs []*nats.Subscription
	conn *nats.Conn

	// DecodeFailures counts messages that did not decode. A malformed message is
	// dropped so it cannot stall the subscription, but it is COUNTED so the drop
	// is observable — a silent vanish would be the missing-evidence failure the
	// system exists to prevent.
	DecodeFailures atomic.Int64
}

// New creates a server over an existing pool.
func New(pool *pgxpool.Pool) *Server { return &Server{pool: pool} }

// Run connects to NATS and subscribes to the telemetry subjects until the
// context is cancelled.
func (s *Server) Run(ctx context.Context, natsURL string) error {
	conn, err := nats.Connect(natsURL)
	if err != nil {
		return fmt.Errorf("controlplane: connecting to NATS: %w", err)
	}
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()

	subjects := []struct {
		subject string
		kind    string
	}{
		{natsx.SubjectEvents, "event"},
		{natsx.SubjectClassification, "classification"},
		{natsx.SubjectDecisions, "decision"},
	}
	for _, sc := range subjects {
		kind := sc.kind
		sub, err := conn.Subscribe(sc.subject, func(m *nats.Msg) {
			s.handle(context.Background(), kind, m.Data)
		})
		if err != nil {
			return fmt.Errorf("controlplane: subscribing %s: %w", sc.subject, err)
		}
		s.mu.Lock()
		s.subs = append(s.subs, sub)
		s.mu.Unlock()
	}

	// Heartbeats (T-018) update last-seen so a silent agent is detectable.
	hbSub, err := conn.Subscribe(natsx.SubjectHeartbeat, func(m *nats.Msg) {
		s.recordHeartbeat(context.Background(), m.Data)
	})
	if err != nil {
		return fmt.Errorf("controlplane: subscribing heartbeats: %w", err)
	}
	s.mu.Lock()
	s.subs = append(s.subs, hbSub)
	s.mu.Unlock()

	<-ctx.Done()
	return s.Close()
}

// handle decodes a message for its index fields and persists the raw payload.
func (s *Server) handle(ctx context.Context, kind string, data []byte) {
	agentID, eventID, ok := decodeIndex(kind, data)
	if !ok {
		s.DecodeFailures.Add(1)
		return
	}
	if err := s.insert(ctx, kind, agentID, eventID, data); err != nil {
		// A persistence failure is also not silent — count it as a decode/handle
		// failure so a full store or a down database is observable.
		s.DecodeFailures.Add(1)
	}
}

// decodeIndex extracts the agent and event ids used for indexing. The payload is
// stored raw regardless — decoding is only to know where to file it.
func decodeIndex(kind string, data []byte) (agentID, eventID string, ok bool) {
	switch kind {
	case "event":
		var e corev1.Event
		if err := proto.Unmarshal(data, &e); err != nil {
			return "", "", false
		}
		return e.GetAgentId(), e.GetEventId(), true
	case "classification":
		var c corev1.ClassificationSummary
		if err := proto.Unmarshal(data, &c); err != nil {
			return "", "", false
		}
		// ClassificationSummary carries no agent id; keyed by event.
		return "", c.GetEventId(), true
	case "decision":
		var d corev1.Decision
		if err := proto.Unmarshal(data, &d); err != nil {
			return "", "", false
		}
		return "", d.GetEventId(), true
	default:
		return "", "", false
	}
}

func (s *Server) insert(ctx context.Context, kind, agentID, eventID string, payload []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload) VALUES ($1,$2,$3,$4)`,
		agentID, kind, eventID, payload)
	return err
}

// Telemetry returns rows for an agent, oldest first.
func (s *Server) Telemetry(ctx context.Context, agentID string) ([]TelemetryRow, error) {
	return s.query(ctx, `SELECT agent_id, kind, event_id, received_at, payload
		FROM fleet_telemetry WHERE agent_id = $1 ORDER BY id ASC`, agentID)
}

// TelemetryForEvent returns rows for an event id, oldest first.
func (s *Server) TelemetryForEvent(ctx context.Context, eventID string) ([]TelemetryRow, error) {
	return s.query(ctx, `SELECT agent_id, kind, event_id, received_at, payload
		FROM fleet_telemetry WHERE event_id = $1 ORDER BY id ASC`, eventID)
}

func (s *Server) query(ctx context.Context, sql, arg string) ([]TelemetryRow, error) {
	rows, err := s.pool.Query(ctx, sql, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TelemetryRow
	for rows.Next() {
		var r TelemetryRow
		if err := rows.Scan(&r.AgentID, &r.Kind, &r.EventID, &r.ReceivedAt, &r.Payload); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Close unsubscribes and closes the NATS connection. The pool is the caller's.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sub := range s.subs {
		_ = sub.Unsubscribe()
	}
	s.subs = nil
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	return nil
}
