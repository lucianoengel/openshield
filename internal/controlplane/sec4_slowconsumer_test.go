package controlplane_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// SEC-4: a slow consumer whose pending queue overflows must have its dropped messages
// COUNTED and surfaced via the async ErrorHandler — never dropped silently. This exercises
// the exact mechanism the control plane installs (nats.ErrorHandler + SetPendingLimits):
// a subscription with a tiny queue and a blocking handler is flooded, and we assert the
// error handler fired (drops observed), not a silent zero.
func TestSlowConsumerDropsAreCounted(t *testing.T) {
	url := embeddedNATS(t)

	var dropped atomic.Int64
	conn, err := nats.Connect(url, nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
		dropped.Add(1)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// A handler that blocks, so the pending queue fills while messages keep arriving.
	release := make(chan struct{})
	sub, err := conn.Subscribe("flood.subject", func(_ *nats.Msg) {
		<-release // block until the test lets go
	})
	if err != nil {
		t.Fatal(err)
	}
	// A deliberately tiny queue so overflow (a drop) happens quickly — the same knob the
	// control plane sets, just small enough to trigger in a test.
	if err := sub.SetPendingLimits(1, 1024); err != nil {
		t.Fatal(err)
	}

	// Flood the subject far past the queue depth. The first message enters the blocked
	// handler; the rest queue, overflow the 1-message limit, and are dropped → ErrorHandler.
	pub, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	for i := 0; i < 5000; i++ {
		_ = pub.Publish("flood.subject", []byte("x"))
	}
	_ = pub.Flush()

	// Wait for the async error handler to fire.
	deadline := time.Now().Add(3 * time.Second)
	for dropped.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	close(release)

	if dropped.Load() == 0 {
		t.Error("a flooded slow consumer dropped messages but the ErrorHandler never fired — SILENT LOSS (SEC-4)")
	}
	_ = context.Background()
}
