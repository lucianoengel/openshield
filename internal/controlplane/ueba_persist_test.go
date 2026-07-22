package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SIEM-5: the peer-UEBA baseline SURVIVES a restart. Observe a population + an outlier on one
// server instance, persist, then bring up a FRESH instance and enable peer-UEBA: it loads the
// persisted baseline, so the outlier's peer risk is preserved — whereas a cold instance that
// never loaded has no baseline at all. This closes the post-restart detection gap.
func TestPeerUEBABaselineSurvivesRestart(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()

	// Instance A: enable, observe a typical population + a heavy outlier, then persist.
	a := controlplane.New(pool)
	a.EnablePeerUEBA(0.5, time.Minute)
	for _, s := range []string{"sub_p1", "sub_p2", "sub_p3", "sub_p4"} {
		for i := 0; i < 10; i++ {
			a.ObserveForTest(s)
		}
	}
	for i := 0; i < 200; i++ {
		a.ObserveForTest("sub_outlier")
	}
	if err := a.PersistBaselines(ctx); err != nil {
		t.Fatalf("PersistBaselines: %v", err)
	}

	// Instance B: a fresh server (the "restart") — loads the persisted baseline on enable.
	b := controlplane.New(pool)
	b.EnablePeerUEBA(0.5, time.Minute)
	if v := b.CurrentContextVersion("sub_outlier"); v == "" {
		t.Fatal("the outlier's baseline did not survive the restart — the fresh instance has no context for it")
	}

	// The restored baseline still flags the outlier as high-risk vs its peers.
	risk := controlplane.PeerRiskForTest(b, "sub_outlier")
	if risk <= 0.5 {
		t.Errorf("restored outlier risk %.3f, want > 0.5 — the baseline did not survive with its shape", risk)
	}
	typ := controlplane.PeerRiskForTest(b, "sub_p1")
	if !(risk > typ) {
		t.Errorf("restored risk not peer-relative after reload: outlier %.3f !> typical %.3f", risk, typ)
	}

	// A COLD instance that never loaded a baseline has none for the subject (the gap this closes).
	// Use a subject that only exists in the persisted set; a brand-new analyzer without the load
	// would return no context. We prove the contrast by clearing the table and re-enabling.
	if _, err := pool.Exec(ctx, `DELETE FROM ueba_baselines`); err != nil {
		t.Fatalf("clearing baselines: %v", err)
	}
	cold := controlplane.New(pool)
	cold.EnablePeerUEBA(0.5, time.Minute)
	if v := cold.CurrentContextVersion("sub_outlier"); v != "" {
		t.Errorf("a cold instance reported a baseline (%q) it never loaded — the contrast is false", v)
	}
}
