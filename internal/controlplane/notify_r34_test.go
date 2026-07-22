package controlplane_test

import (
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/notify"
)

// TestUnconfiguredServerDoesNotFillNotifyQueue (R34-9): a server with no notifier
// configured must NOT enqueue alerts into a never-drained queue — emitting far more
// than the queue capacity must drop none and spam nothing.
func TestUnconfiguredServerDoesNotFillNotifyQueue(t *testing.T) {
	srv := controlplane.New(requireDB(t)) // no SetNotifier → delivery loop not running

	// Emit well past the 256-slot queue capacity.
	for i := 0; i < 1000; i++ {
		srv.EmitForTest(notify.Notification{Kind: "peer_alert", Subject: "sub", ID: string(rune('a' + i%26))})
	}
	if n := srv.NotifyDropped.Load(); n != 0 {
		t.Fatalf("NotifyDropped = %d, want 0 — an unconfigured server must not enqueue (R34-9)", n)
	}
}
