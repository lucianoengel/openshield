// Package nats implements core.Transport over NATS JetStream.
//
// This is the agent↔control-plane boundary ONLY. It is deliberately not used
// inside the endpoint pipeline: the fanotify permission responder answers while
// a real process is blocked in TASK_UNINTERRUPTIBLE, and T-002 measured that
// budget at 1-3µs typical / 532µs worst case. A broker round trip does not fit,
// and local-first evaluation means it should not have to.
//
// internal/core must never import this package. CI asserts it.
package nats

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

const (
	SubjectEvents         = "openshield.v1.events"
	SubjectClassification = "openshield.v1.classifications"
	SubjectDecisions      = "openshield.v1.decisions"
)

// Transport publishes wire-form messages to the control plane.
//
// Note which types have methods here: Event, ClassificationSummary and
// Decision. There is no method accepting LocalClassification, and that absence
// is the enforcement — a redaction step at the boundary would be a runtime
// behaviour that can be skipped; a missing method is a compile error.
type Transport struct {
	conn *nats.Conn
	// PublishTimeout bounds each publish. The pipeline may be running while a
	// process is blocked in the kernel, so a transport that blocks on a network
	// write would move a network problem into the syscall path.
	PublishTimeout time.Duration
}

// Connect dials NATS. A failure to connect is returned, not retried silently —
// an agent that cannot reach the control plane should say so.
func Connect(url string, opts ...nats.Option) (*Transport, error) {
	c, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrUnreachable, err)
	}
	return &Transport{conn: c, PublishTimeout: 2 * time.Second}, nil
}

func (t *Transport) publish(ctx context.Context, subject string, m proto.Message) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", subject, err)
	}

	if t.conn == nil || t.conn.IsClosed() {
		// Explicit, never silent. Until T-024 provides a durable queue there is
		// nowhere to put this payload, and pretending otherwise would turn a
		// network problem into missing evidence — which is indistinguishable
		// from "nothing happened".
		return fmt.Errorf("%w: %w", core.ErrUnreachable, core.ErrPayloadDropped)
	}

	deadline := t.PublishTimeout
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d < deadline {
			deadline = d
		}
	}
	if deadline <= 0 {
		return fmt.Errorf("%w: no time budget remaining", core.ErrUnreachable)
	}

	done := make(chan error, 1)
	go func() { done <- t.conn.Publish(subject, b) }()

	select {
	case err := <-done:
		if err != nil {
			if errors.Is(err, nats.ErrConnectionClosed) || errors.Is(err, nats.ErrNoServers) {
				return fmt.Errorf("%w: %v", core.ErrUnreachable, err)
			}
			return err
		}
		return nil
	case <-time.After(deadline):
		return fmt.Errorf("%w: publish exceeded %s", core.ErrUnreachable, deadline)
	case <-ctx.Done():
		return fmt.Errorf("%w: %v", core.ErrUnreachable, ctx.Err())
	}
}

func (t *Transport) PublishEvent(ctx context.Context, e *corev1.Event) error {
	return t.publish(ctx, SubjectEvents, e)
}

// PublishClassification takes the SUMMARY. There is deliberately no overload
// accepting LocalClassification — see the package comment and D10.
func (t *Transport) PublishClassification(ctx context.Context, c *corev1.ClassificationSummary) error {
	return t.publish(ctx, SubjectClassification, c)
}

func (t *Transport) PublishDecision(ctx context.Context, d *corev1.Decision) error {
	return t.publish(ctx, SubjectDecisions, d)
}

func (t *Transport) Close() error {
	if t.conn != nil {
		t.conn.Close()
	}
	return nil
}

// Compile-time proof that this satisfies the interface defined in core.
var _ core.Transport = (*Transport)(nil)
