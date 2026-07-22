package controlplane_test

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SIEM-5b: loadBaselines skips a corrupt persisted row (non-finite/negative count, or a future
// last-seen) so it never enters the analyzer — reachable only with DB write access, but a NaN would
// poison every z-score.
func TestLoadBaselinesSkipsCorruptRows(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `DELETE FROM ueba_baselines`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rows := []struct {
		sub   string
		count float64
		last  time.Time
	}{
		{"sub_ok", 5, now.Add(-time.Minute)},
		{"sub_nan", math.NaN(), now},
		{"sub_neg", -3, now},
		{"sub_future", 5, now.Add(time.Hour)},
	}
	for _, r := range rows {
		if _, err := pool.Exec(ctx,
			`INSERT INTO ueba_baselines (subject, count, last_seen, updated_at) VALUES ($1,$2,$3,now())`,
			r.sub, r.count, r.last); err != nil {
			t.Fatalf("insert %s: %v", r.sub, err)
		}
	}

	s := controlplane.New(pool)
	states, err := controlplane.LoadBaselinesForTest(s, ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := map[string]bool{}
	for _, st := range states {
		got[st.Subject] = true
	}
	if !got["sub_ok"] {
		t.Error("the valid baseline row was not loaded")
	}
	for _, bad := range []string{"sub_nan", "sub_neg", "sub_future"} {
		if got[bad] {
			t.Errorf("a corrupt row %q was loaded — on-load validation is not applied", bad)
		}
	}
}

// SIEM-5b: PersistBaselines prunes a decayed-below-threshold subject and DELETEs its row, so the
// table does not grow without bound; an active subject's row survives.
func TestPersistPrunesDecayedRows(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `DELETE FROM ueba_baselines`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, r := range []struct {
		sub   string
		count float64
		last  time.Time
	}{
		{"sub_cold", 1, now.Add(-100 * time.Hour)}, // DefaultHalfLife=1h → decays to ≈ 0
		{"sub_active", 10, now},
	} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO ueba_baselines (subject, count, last_seen, updated_at) VALUES ($1,$2,$3,now())`,
			r.sub, r.count, r.last); err != nil {
			t.Fatalf("insert %s: %v", r.sub, err)
		}
	}

	s := controlplane.New(pool)
	s.EnablePeerUEBA(0.5, time.Minute) // loads both rows
	if err := s.PersistBaselines(ctx); err != nil {
		t.Fatalf("persist: %v", err)
	}

	count := func(sub string) int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM ueba_baselines WHERE subject=$1`, sub).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", sub, err)
		}
		return n
	}
	if count("sub_cold") != 0 {
		t.Error("the decayed subject's row was not pruned on persist — the table grows without bound")
	}
	if count("sub_active") != 1 {
		t.Error("the active subject's row was wrongly removed")
	}
}
