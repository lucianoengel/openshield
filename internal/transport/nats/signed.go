package nats

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/core"
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

	// spool is the durable offline queue (D40/D67): when the control plane is
	// unreachable the SIGNED envelope bytes are stored and re-published verbatim
	// on Flush — the sequence and signature are baked in, so a late message
	// verifies exactly as a live one (a gap at worst, D50). send/connected are
	// seams so the store-or-forward logic is testable without a live broker.
	spool     Spool
	send      func([]byte) error
	connected func() bool
}

// Spool is the durable store-and-forward interface the publisher needs (satisfied
// by *queue.Queue): FIFO, bounded, crash-safe.
type Spool interface {
	Enqueue(rec []byte) error
	Drain(fn func([]byte) error) (int, error)
	Len() int
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
	return p.storeOrSend(b)
}

// SetSpool attaches a durable offline queue: when the control plane is
// unreachable, signed envelopes are stored and re-sent on Flush, so telemetry is
// not silently lost during an outage (D67). Without a spool, an unreachable
// publish returns an error (unchanged).
func (p *SignedPublisher) SetSpool(s Spool) { p.spool = s }

// storeOrSend publishes directly when connected and the spool is empty, else
// durably enqueues — preserving FIFO order (a new message goes BEHIND anything
// already queued, so the control plane sees events in the order produced).
func (p *SignedPublisher) storeOrSend(b []byte) error {
	if p.spool == nil {
		return p.sendFn()(b)
	}
	if p.spool.Len() > 0 || !p.connectedFn()() {
		return p.spool.Enqueue(b)
	}
	if err := p.sendFn()(b); err != nil {
		return p.spool.Enqueue(b) // an outage mid-send must not lose the payload
	}
	return nil
}

// Flush re-sends every spooled envelope in order, stopping at the first failure
// (keeping the undelivered tail for a later Flush). Returns the number delivered.
func (p *SignedPublisher) Flush() (int, error) {
	if p.spool == nil {
		return 0, nil
	}
	return p.spool.Drain(p.sendFn())
}

// sendFn/connectedFn resolve the seams: an injected override (tests) or the live
// NATS connection. An absent/closed connection is ErrUnreachable so storeOrSend
// enqueues rather than erroring.
func (p *SignedPublisher) sendFn() func([]byte) error {
	if p.send != nil {
		return p.send
	}
	return func(b []byte) error {
		if p.conn == nil || p.conn.IsClosed() {
			return core.ErrUnreachable
		}
		return p.conn.Publish(SubjectSigned, b)
	}
}

func (p *SignedPublisher) connectedFn() func() bool {
	if p.connected != nil {
		return p.connected
	}
	return func() bool { return p.conn != nil && p.conn.IsConnected() }
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
