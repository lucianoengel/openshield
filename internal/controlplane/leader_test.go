package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// PLAT-2b: exactly one instance is elected leader; a standby blocks while the leader holds the lock,
// and takes over when the leader steps down (failover). Two independent pools model two processes.
func TestLeaderElectionAndFailover(t *testing.T) {
	pool1 := requireDB(t)
	pool2, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool2.Close()

	const poll = 100 * time.Millisecond
	l1 := controlplane.NewLeaderForTest(pool1, poll)
	l2 := controlplane.NewLeaderForTest(pool2, poll)

	// Instance 1 acquires leadership and holds it until its context is cancelled.
	ctx1, cancel1 := context.WithCancel(context.Background())
	elected1 := make(chan struct{}, 1)
	go func() { _ = l1.Run(ctx1, func(lc context.Context) { elected1 <- struct{}{}; <-lc.Done() }) }()
	select {
	case <-elected1:
	case <-time.After(5 * time.Second):
		cancel1()
		t.Fatal("instance 1 was not elected leader")
	}

	// Instance 2 starts — it MUST NOT be elected while instance 1 holds the lock (no split-brain).
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	elected2 := make(chan struct{}, 1)
	go func() { _ = l2.Run(ctx2, func(lc context.Context) { elected2 <- struct{}{}; <-lc.Done() }) }()
	select {
	case <-elected2:
		cancel1()
		t.Fatal("SPLIT-BRAIN: instance 2 was elected while instance 1 is still leader")
	case <-time.After(1 * time.Second):
		// good — instance 2 is blocked, polling for the lock
	}

	// Failover: instance 1 steps down (releases the lock) → instance 2 must be elected.
	cancel1()
	select {
	case <-elected2:
		// takeover succeeded
	case <-time.After(5 * time.Second):
		t.Fatal("instance 2 was not elected after instance 1 stepped down — failover failed (a lingering lock?)")
	}
}

// PLAT-2b: a single instance (the non-HA case) is elected immediately and its leaderCtx is cancelled
// when the process context is cancelled.
func TestSingleLeaderElectedImmediately(t *testing.T) {
	pool := requireDB(t)
	l := controlplane.NewLeaderForTest(pool, 100*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())

	elected := make(chan struct{}, 1)
	leaderCtxDone := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		_ = l.Run(ctx, func(lc context.Context) {
			elected <- struct{}{}
			<-lc.Done()
			leaderCtxDone <- struct{}{}
		})
		close(done)
	}()
	select {
	case <-elected:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("the sole instance was not elected immediately")
	}
	cancel()
	select {
	case <-leaderCtxDone:
	case <-time.After(5 * time.Second):
		t.Fatal("leaderCtx did not cancel when the process context was cancelled")
	}
	<-done
}
