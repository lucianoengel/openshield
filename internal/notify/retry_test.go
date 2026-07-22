package notify

import (
	"context"
	"errors"
	"testing"
	"time"
)

// countingNotifier fails for the first failUntil calls, then succeeds. It records every attempt.
type countingNotifier struct {
	attempts  int
	failUntil int
	err       error // the error returned while failing (transient by default)
}

func (c *countingNotifier) Notify(context.Context, Notification) error {
	c.attempts++
	if c.attempts <= c.failUntil {
		return c.err
	}
	return nil
}

// instantSleep is the injected backoff: it never actually waits, but honors cancellation, so the
// retry logic is exercised deterministically without real delays.
func instantSleep(ctx context.Context, _ time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// SIEM-8: a transient failure is retried until it succeeds within the attempt budget.
func TestRetrySucceedsAfterTransientFailures(t *testing.T) {
	inner := &countingNotifier{failUntil: 2, err: errors.New("503 transient")}
	r := &Retrying{Inner: inner, MaxAttempts: 3, BaseDelay: time.Millisecond, sleep: instantSleep}
	if err := r.Notify(context.Background(), Notification{}); err != nil {
		t.Fatalf("delivery failed despite a retry budget: %v", err)
	}
	if inner.attempts != 3 {
		t.Errorf("attempts = %d, want 3 (two failures then a success)", inner.attempts)
	}
}

// The attempt budget is bounded: a persistently failing sink is tried exactly MaxAttempts times,
// then the final error is returned (best-effort, not infinite).
func TestRetryExhaustsBudget(t *testing.T) {
	inner := &countingNotifier{failUntil: 99, err: errors.New("always down")}
	r := &Retrying{Inner: inner, MaxAttempts: 4, BaseDelay: time.Millisecond, sleep: instantSleep}
	if err := r.Notify(context.Background(), Notification{}); err == nil {
		t.Fatal("a persistently failing sink returned nil")
	}
	if inner.attempts != 4 {
		t.Errorf("attempts = %d, want exactly 4 (bounded)", inner.attempts)
	}
}

// A PERMANENT failure is not retried — retrying a 4xx wastes the budget for no chance of success.
func TestRetryDoesNotRetryPermanent(t *testing.T) {
	inner := &countingNotifier{failUntil: 99, err: Permanent(errors.New("400 bad request"))}
	r := &Retrying{Inner: inner, MaxAttempts: 5, BaseDelay: time.Millisecond, sleep: instantSleep}
	if err := r.Notify(context.Background(), Notification{}); err == nil {
		t.Fatal("a permanent failure returned nil")
	}
	if inner.attempts != 1 {
		t.Errorf("attempts = %d, want exactly 1 (a permanent error is not retried)", inner.attempts)
	}
}

// A cancelled context stops retrying promptly rather than sleeping out the backoff window.
func TestRetryHonorsContextCancellation(t *testing.T) {
	inner := &countingNotifier{failUntil: 99, err: errors.New("down")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	r := &Retrying{Inner: inner, MaxAttempts: 5, BaseDelay: time.Hour, sleep: sleepCtx}
	err := r.Notify(ctx, Notification{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	// The first attempt runs, then backoff hits the cancelled context and returns — so at most
	// one attempt, never blocking on the 1h backoff.
	if inner.attempts != 1 {
		t.Errorf("attempts = %d, want 1 (cancelled before the retry)", inner.attempts)
	}
}
