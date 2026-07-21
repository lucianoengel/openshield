package nats

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/transport/queue"
)

type fakeSigner struct{}

func (fakeSigner) Sign(seq uint64, payload []byte) []byte { return []byte("sig") }

// 3.1 — with the connection DOWN, published telemetry is spooled (none lost); on
// recovery, Flush delivers it IN ORDER, byte-for-byte (D67).
func TestSpoolStoreAndForward(t *testing.T) {
	q, err := queue.Open(t.TempDir(), 100, func(uint64) {})
	if err != nil {
		t.Fatal(err)
	}
	var delivered [][]byte
	down := true
	p := &SignedPublisher{agentID: "a", id: fakeSigner{}, spool: q,
		send: func(b []byte) error {
			if down {
				return core.ErrUnreachable
			}
			delivered = append(delivered, append([]byte(nil), b...))
			return nil
		},
		connected: func() bool { return !down },
	}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := p.PublishEvent(ctx, &corev1.Event{EventId: fmt.Sprintf("e%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if q.Len() != 3 {
		t.Fatalf("during the outage %d were queued, want 3 (silent loss otherwise)", q.Len())
	}
	if len(delivered) != 0 {
		t.Fatal("a message was delivered during the outage")
	}

	down = false
	n, err := p.Flush()
	if err != nil || n != 3 {
		t.Fatalf("flush delivered %d (err %v), want 3", n, err)
	}
	if len(delivered) != 3 || q.Len() != 0 {
		t.Fatalf("after flush: delivered=%d queued=%d", len(delivered), q.Len())
	}
	// Delivered in order, exact bytes (sequence intact).
	var last uint64
	for _, b := range delivered {
		var env corev1.SignedTelemetry
		if err := proto.Unmarshal(b, &env); err != nil {
			t.Fatal(err)
		}
		if env.Sequence <= last {
			t.Fatalf("out of order: seq %d after %d", env.Sequence, last)
		}
		last = env.Sequence
	}
}

// 3.2 — FIFO preserved: while the spool is non-empty, a new message goes BEHIND
// the queued ones even though the connection is up (never races ahead).
func TestSpoolFIFOWhenConnected(t *testing.T) {
	q, _ := queue.Open(t.TempDir(), 100, func(uint64) {})
	_ = q.Enqueue([]byte("already-queued"))
	var delivered int
	p := &SignedPublisher{agentID: "a", id: fakeSigner{}, spool: q,
		send:      func([]byte) error { delivered++; return nil },
		connected: func() bool { return true }, // connection is UP
	}
	if err := p.PublishEvent(context.Background(), &corev1.Event{EventId: "new"}); err != nil {
		t.Fatal(err)
	}
	if delivered != 0 {
		t.Error("a new message raced ahead of the queued backlog")
	}
	if q.Len() != 2 {
		t.Fatalf("queued=%d, want 2 (backlog + the new message behind it)", q.Len())
	}
}

// 3.3 — a bounded-queue overflow fires the LOUD callback (no silent loss, D31).
func TestSpoolOverflowIsLoud(t *testing.T) {
	dropped := []uint64{}
	q, _ := queue.Open(t.TempDir(), 2, func(seq uint64) { dropped = append(dropped, seq) })
	for i := 0; i < 3; i++ {
		if err := q.Enqueue([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if len(dropped) == 0 {
		t.Fatal("overflow dropped a record SILENTLY — the callback did not fire")
	}
}
