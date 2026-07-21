package nats

import (
	"context"
	"fmt"
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
type SignedPublisher struct {
	agentID string
	id      signer
	conn    *nats.Conn
	seq     atomic.Uint64
}

// NewSignedPublisher wraps an agent identity over a NATS connection.
func NewSignedPublisher(agentID string, id *identity.Identity, conn *nats.Conn) *SignedPublisher {
	return &SignedPublisher{agentID: agentID, id: id, conn: conn}
}

func (p *SignedPublisher) publish(kind string, m proto.Message) error {
	payload, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	seq := p.seq.Add(1)
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
