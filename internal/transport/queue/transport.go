package queue

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// payload kinds, tagged so a drained record can be routed to the right Publish
// method on the inner transport.
const (
	kindEvent          = 1
	kindClassification = 2
	kindDecision       = 3
)

// QueueingTransport wraps a Transport with the durable spool, implementing
// core.Transport so callers are unchanged (the seam was shaped for this, D24).
//
// The rule that preserves order: if anything is queued, a new payload goes
// BEHIND it rather than racing ahead on a recovered connection — the control
// plane must see events in the order the agent produced them.
type QueueingTransport struct {
	inner core.Transport
	q     *Queue
}

// Wrap returns a QueueingTransport over an inner transport and an opened queue.
func Wrap(inner core.Transport, q *Queue) *QueueingTransport {
	return &QueueingTransport{inner: inner, q: q}
}

func encode(kind byte, m proto.Message) ([]byte, error) {
	b, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(b)+1)
	out = append(out, kind)
	out = append(out, b...)
	return out, nil
}

// store-or-send: enqueue if the queue is non-empty (preserve FIFO) or if the
// inner transport is unreachable; otherwise publish directly. Enqueue returns
// success because the payload is now durably held — that is the guarantee.
func (t *QueueingTransport) storeOrSend(rec []byte, direct func() error) error {
	if t.q.Len() > 0 {
		return t.q.Enqueue(rec)
	}
	err := direct()
	if err == nil {
		return nil
	}
	if errors.Is(err, core.ErrUnreachable) {
		return t.q.Enqueue(rec)
	}
	return err // a non-connectivity error is the caller's to handle
}

func (t *QueueingTransport) PublishEvent(ctx context.Context, e *corev1.Event) error {
	rec, err := encode(kindEvent, e)
	if err != nil {
		return err
	}
	return t.storeOrSend(rec, func() error { return t.inner.PublishEvent(ctx, e) })
}

func (t *QueueingTransport) PublishClassification(ctx context.Context, c *corev1.ClassificationSummary) error {
	rec, err := encode(kindClassification, c)
	if err != nil {
		return err
	}
	return t.storeOrSend(rec, func() error { return t.inner.PublishClassification(ctx, c) })
}

func (t *QueueingTransport) PublishDecision(ctx context.Context, d *corev1.Decision) error {
	rec, err := encode(kindDecision, d)
	if err != nil {
		return err
	}
	return t.storeOrSend(rec, func() error { return t.inner.PublishDecision(ctx, d) })
}

// Flush drains the spool to the inner transport in order. It stops at the first
// unreachable/error, keeping the undelivered tail for a later Flush.
func (t *QueueingTransport) Flush(ctx context.Context) (int, error) {
	return t.q.Drain(func(rec []byte) error {
		if len(rec) < 1 {
			return fmt.Errorf("queue: empty record")
		}
		kind, body := rec[0], rec[1:]
		switch kind {
		case kindEvent:
			var e corev1.Event
			if err := proto.Unmarshal(body, &e); err != nil {
				return err
			}
			return t.inner.PublishEvent(ctx, &e)
		case kindClassification:
			var c corev1.ClassificationSummary
			if err := proto.Unmarshal(body, &c); err != nil {
				return err
			}
			return t.inner.PublishClassification(ctx, &c)
		case kindDecision:
			var d corev1.Decision
			if err := proto.Unmarshal(body, &d); err != nil {
				return err
			}
			return t.inner.PublishDecision(ctx, &d)
		default:
			return fmt.Errorf("queue: unknown payload kind %d", kind)
		}
	})
}

// Close closes the inner transport. The spool persists on disk for the next run.
func (t *QueueingTransport) Close() error { return t.inner.Close() }

var _ core.Transport = (*QueueingTransport)(nil)
