package gateway

import (
	"context"
	"testing"
)

// TestSuperviseReArmsUntilCancel: the loop re-arms after each arm returns and exits only on ctx cancel —
// the self-heal behavior. Here arm returns immediately (a repeatedly-dying plane); backoff cancels the ctx
// after N iterations. arm must have been called N times.
//
// Mutation (loop returns after the first arm instead of re-looping): arm is called once → this FAILs.
func TestSuperviseReArmsUntilCancel(t *testing.T) {
	const N = 4
	ctx, cancel := context.WithCancel(context.Background())
	arms := 0
	arm := func(context.Context) error { arms++; return nil }
	backoff := func(context.Context) bool {
		if arms >= N {
			cancel()
			return false // ctx done during the wait
		}
		return true
	}
	superviseTProxy(ctx, arm, backoff, nil)
	if arms != N {
		t.Fatalf("arm called %d times, want %d (the plane must re-arm after each stop until cancel)", arms, N)
	}
}

// TestSuperviseExitsOnBackoffCancel: backoff returning false (ctx cancelled during the wait) exits promptly.
func TestSuperviseExitsOnBackoffCancel(t *testing.T) {
	arms := 0
	arm := func(context.Context) error { arms++; return nil }
	superviseTProxy(context.Background(), arm, func(context.Context) bool { return false }, nil)
	if arms != 1 {
		t.Fatalf("arm called %d times, want 1 (one arm, then backoff-cancel exits)", arms)
	}
}

// TestSuperviseNoArmWhenAlreadyCancelled: a context cancelled before entry never arms.
func TestSuperviseNoArmWhenAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	arms := 0
	superviseTProxy(ctx, func(context.Context) error { arms++; return nil }, func(context.Context) bool { return true }, nil)
	if arms != 0 {
		t.Fatalf("arm called %d times on an already-cancelled ctx, want 0", arms)
	}
}
