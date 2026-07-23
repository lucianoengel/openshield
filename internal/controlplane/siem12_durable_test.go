package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/notify"
)

// chanNotifier records delivered notification ids on a channel, so a test can assert exactly which
// alerts were delivered (vs. suppressed).
type chanNotifier struct{ ids chan string }

func (c *chanNotifier) Notify(_ context.Context, n notify.Notification) error {
	c.ids <- n.ID
	return nil
}

func deliveredID(t *testing.T, c *chanNotifier) string {
	t.Helper()
	select {
	case id := <-c.ids:
		return id
	case <-time.After(2 * time.Second):
		t.Fatal("expected a delivery, got none")
		return ""
	}
}

func noDelivery(t *testing.T, c *chanNotifier) {
	t.Helper()
	select {
	case id := <-c.ids:
		t.Fatalf("expected NO delivery (durable dedup), but delivered %q", id)
	case <-time.After(400 * time.Millisecond):
	}
}

// peerAlert builds the notification emit stamps for a peer alert — a fixed At makes the derived id
// deterministic across server instances (the "same logical alert" the dedup must collapse).
func peerAlert(subject string, at time.Time) notify.Notification {
	return notify.Notification{Kind: notify.KindPeerAlert, Subject: subject, At: at}
}

// TestDurableDedupeSurvivesRestart (SIEM-12/R34-13): a logical alert delivered by one server must NOT
// be re-paged by a FRESH server on the SAME database — the restart/failover double-page the in-memory
// dedup could not prevent. Two Server instances on one pool model "restart": the second has an empty
// in-memory set but shares the durable ledger.
//
// Mutation: if emit ignored the durable result (or markNotifyDurable treated a conflict as new), the
// second server would deliver a second page → noDelivery FAILs.
func TestDurableDedupeSurvivesRestart(t *testing.T) {
	pool := requireDB(t)
	at := time.Unix(1_700_000_000, 0).UTC()

	// Server A delivers the alert (and records it durably).
	recA := &chanNotifier{ids: make(chan string, 8)}
	srvA := controlplane.New(pool)
	srvA.SetNotifier(recA)
	srvA.EmitForTest(peerAlert("alice", at))
	id := deliveredID(t, recA)
	if id == "" {
		t.Fatal("server A did not deliver the first page")
	}

	// Server B is a FRESH instance (empty in-memory dedup) on the SAME database — a restart. The same
	// logical alert must be suppressed by the durable ledger, not re-paged.
	recB := &chanNotifier{ids: make(chan string, 8)}
	srvB := controlplane.New(pool)
	srvB.SetNotifier(recB)
	srvB.EmitForTest(peerAlert("alice", at))
	noDelivery(t, recB)
	if got := srvB.NotifyDeduped.Load(); got != 1 {
		t.Errorf("server B NotifyDeduped = %d, want 1 (the cross-restart duplicate)", got)
	}
}

// TestDurableDedupeFailsOpen (SIEM-12/R34-13): when the durable layer is unavailable (a closed pool),
// the alert is STILL delivered — a missed page is worse than a rare double-page. The in-memory decision
// stands.
//
// Mutation: if emit suppressed on a durable ERROR (treating an error as "duplicate"), the alert would
// be dropped → deliveredID times out and FAILs.
func TestDurableDedupeFailsOpen(t *testing.T) {
	pool := requireDB(t)
	pool.Close() // the durable insert will now error on every emit

	rec := &chanNotifier{ids: make(chan string, 8)}
	srv := controlplane.New(pool)
	srv.SetNotifier(rec)
	srv.EmitForTest(peerAlert("bob", time.Unix(1_700_000_500, 0).UTC()))
	if id := deliveredID(t, rec); id == "" {
		t.Fatal("a durable-layer outage dropped the page — fail-open violated")
	}
}

// TestDurableDedupePrune (SIEM-12/R34-13): pruning aged ids lets a genuinely-later occurrence of the
// same logical alert page again (the ledger only needs to outlive the dedup window).
func TestDurableDedupePrune(t *testing.T) {
	pool := requireDB(t)
	at := time.Unix(1_700_001_000, 0).UTC()

	rec := &chanNotifier{ids: make(chan string, 8)}
	srv := controlplane.New(pool)
	srv.SetNotifier(rec)

	srv.EmitForTest(peerAlert("carol", at))
	first := deliveredID(t, rec)

	// A fresh server (empty in-memory) would suppress via the durable ledger...
	srv2 := controlplane.New(pool)
	rec2 := &chanNotifier{ids: make(chan string, 8)}
	srv2.SetNotifier(rec2)
	srv2.EmitForTest(peerAlert("carol", at))
	noDelivery(t, rec2)

	// ...until the id is pruned; after pruning everything, the same id pages again.
	if _, err := srv2.PruneNotifyDedupe(context.Background(), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("prune: %v", err)
	}
	srv3 := controlplane.New(pool)
	rec3 := &chanNotifier{ids: make(chan string, 8)}
	srv3.SetNotifier(rec3)
	srv3.EmitForTest(peerAlert("carol", at))
	if again := deliveredID(t, rec3); again != first {
		t.Fatalf("after pruning, the same alert should page again with the same id (got %q, want %q)", again, first)
	}
}
