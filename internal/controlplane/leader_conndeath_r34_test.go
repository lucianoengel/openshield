package controlplane_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// TestLeaderRecoversFromConnDeath (R34-6, test proposal #7): when the LEADER's held connection is
// killed out from under it (a Postgres backend termination — the real conn-death the lease relies
// on), the leader must NOTICE (its hold ping fails), step down, and re-establish leadership rather
// than stall forever holding a dead connection. This is the conn-death failover the PLAT-2b ticket
// claims and R34-6 found untested.
//
// A single instance is used so the assertion is race-free: it must be elected AGAIN after its
// connection dies. Mutation: if `hold` does not cancel leaderCtx on a failed ping, the leader hangs
// on the dead connection and the second election never fires — this FAILS.
func TestLeaderRecoversFromConnDeath(t *testing.T) {
	pool := requireDB(t)
	const poll = 100 * time.Millisecond
	l := controlplane.NewLeaderForTest(pool, poll)

	var elections int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	elected := make(chan int32, 4)
	go func() {
		_ = l.Run(ctx, func(lc context.Context) {
			n := atomic.AddInt32(&elections, 1)
			elected <- n
			<-lc.Done()
		})
	}()

	// First election.
	select {
	case <-elected:
	case <-time.After(5 * time.Second):
		t.Fatal("instance was not elected initially")
	}

	// Kill the backend HOLDING the advisory lock (classid/objid encode the 64-bit key; ours fits in
	// objid). A separate pooled connection issues the terminate — this is the conn-death the lease
	// depends on Postgres detecting.
	key := controlplane.LeaderLockKey()
	classid := int32(key >> 32)
	objid := int32(key & 0xFFFFFFFF)
	kctx, kcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer kcancel()
	tag, err := pool.Exec(kctx,
		`SELECT pg_terminate_backend(pid) FROM pg_locks
		  WHERE locktype='advisory' AND classid=$1 AND objid=$2 AND objsubid=1 AND granted`,
		classid, objid)
	if err != nil {
		t.Fatalf("terminating the leader's backend: %v", err)
	}
	if tag.RowsAffected() == 0 {
		t.Fatal("found no backend holding the leader advisory lock to terminate")
	}

	// The leader must detect the dead connection, step down, and be RE-elected (the lock was released
	// by Postgres when the backend died).
	select {
	case n := <-elected:
		if n < 2 {
			t.Fatalf("re-election reported election #%d, want >= 2", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("leader did not recover after its connection died — conn-death failover is broken (a lingering lock or an undetected dead lease)")
	}
}
