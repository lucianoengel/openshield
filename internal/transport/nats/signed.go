package nats

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// SubjectSigned carries signed telemetry envelopes (T-017).
const SubjectSigned = "openshield.v1.signed"

// signer is the subset of the agent identity the publisher needs.
type signer interface {
	Sign(seq uint64, payload []byte) []byte
}

// SignedPublisher signs and publishes an agent's telemetry. It holds ONE
// monotonic sequence across all kinds, so a dropped message of any kind leaves a
// detectable hole in the stream the control plane verifies.
//
// With a SeqStore the sequence is PERSISTED (D66): a restart resumes from the
// last reserved high-water and never reuses a sequence, so a routine restart is
// forward-monotonic (a gap at worst, D50), not a false replay. Without one the
// counter is in-memory (fine for tests and short-lived callers).
type SignedPublisher struct {
	agentID string
	id      signer
	conn    *nats.Conn
	seq     atomic.Uint64

	mu    sync.Mutex // guards the reservation high-water
	store SeqStore
	hw    uint64 // persisted high-water; seq may advance up to hw without a write
}

// NewSignedPublisher wraps an agent identity over a NATS connection with an
// in-memory (non-persisted) sequence.
func NewSignedPublisher(agentID string, id *identity.Identity, conn *nats.Conn) *SignedPublisher {
	return &SignedPublisher{agentID: agentID, id: id, conn: conn}
}

// NewSignedPublisherWithSeq persists the sequence via store: it loads the last
// reserved high-water and resumes there, so a restart never reuses a sequence
// (D66). A corrupt store is a loud error — better to refuse than to reset to 0
// and reintroduce the false-replay bug.
func NewSignedPublisherWithSeq(agentID string, id *identity.Identity, conn *nats.Conn, store SeqStore) (*SignedPublisher, error) {
	hw, err := store.Load()
	if err != nil {
		return nil, err
	}
	p := &SignedPublisher{agentID: agentID, id: id, conn: conn, store: store, hw: hw}
	p.seq.Store(hw) // resume AHEAD of anything previously used (all <= hw)
	return p, nil
}

// nextSeq returns the next monotonic sequence, reserving a new persisted block
// when the counter crosses the current high-water.
func (p *SignedPublisher) nextSeq() (uint64, error) {
	s := p.seq.Add(1)
	if p.store == nil {
		return s, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if s > p.hw {
		newHW := s + reserveBlock
		if err := p.store.Reserve(newHW); err != nil {
			return 0, err
		}
		p.hw = newHW
	}
	return s, nil
}

func (p *SignedPublisher) publish(kind string, m proto.Message) error {
	payload, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	seq, err := p.nextSeq()
	if err != nil {
		return fmt.Errorf("signed publisher: reserving sequence: %w", err)
	}
	env := &corev1.SignedTelemetry{
		AgentId: p.agentID, Sequence: seq, Kind: kind,
		Payload: payload, Signature: p.id.Sign(seq, payload),
	}
	b, err := proto.Marshal(env)
	if err != nil {
		return err
	}
	if p.conn == nil || p.conn.IsClosed() {
		return fmt.Errorf("signed publisher: connection closed")
	}
	return p.conn.Publish(SubjectSigned, b)
}

func (p *SignedPublisher) PublishEvent(_ context.Context, e *corev1.Event) error {
	return p.publish("event", e)
}
func (p *SignedPublisher) PublishClassification(_ context.Context, c *corev1.ClassificationSummary) error {
	return p.publish("classification", c)
}
func (p *SignedPublisher) PublishDecision(_ context.Context, d *corev1.Decision) error {
	return p.publish("decision", d)
}

// PublishHeartbeat signs and publishes the agent's liveness signal (T-018) so a
// verified heartbeat advances last-seen — a silent agent is detectable AND the
// heartbeat is attributable, not self-asserted.
func (p *SignedPublisher) PublishHeartbeat(_ context.Context, h *corev1.Heartbeat) error {
	return p.publish("heartbeat", h)
}
