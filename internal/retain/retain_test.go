package retain_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/retain"
)

// Loop invokes fn on the interval and stops on context cancellation.
func TestLoopTicksThenStops(t *testing.T) {
	var n atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { retain.Loop(ctx, 10*time.Millisecond, func(context.Context) { n.Add(1) }); close(done) }()
	time.Sleep(55 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Loop did not return on cancellation")
	}
	if got := n.Load(); got < 2 {
		t.Errorf("fn ran %d times in ~55ms at 10ms interval, want >=2", got)
	}
}

// A non-positive interval disables the loop (returns immediately, never spins).
func TestLoopDisabledOnZeroInterval(t *testing.T) {
	var n atomic.Int64
	retain.Loop(context.Background(), 0, func(context.Context) { n.Add(1) })
	if n.Load() != 0 {
		t.Error("Loop with a zero interval ran fn — it must be disabled")
	}
}
