package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// F1: the operator searches the fleet's peer alerts by subject, risk, and time, with the
// filter applied as parameterized SQL — an injection-shaped subject is treated as data.
func TestSearchPeerAlerts(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	base := time.Now().UTC().Truncate(time.Second)
	// Seed a spread of alerts across subjects, risk, and time.
	rows := []struct {
		subject string
		risk    float64
		age     time.Duration
	}{
		{"sub_alice", 0.95, 1 * time.Hour},
		{"sub_alice", 0.40, 10 * time.Minute},
		{"sub_bob", 0.99, 30 * time.Minute},
		{"sub_carol", 0.20, 2 * time.Hour},
	}
	for _, r := range rows {
		if _, err := pool.Exec(ctx,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, detected_at)
			 VALUES ($1,$2,'v1',$3)`, r.subject, r.risk, base.Add(-r.age)); err != nil {
			t.Fatal(err)
		}
	}

	// By subject.
	got, err := srv.SearchPeerAlerts(ctx, controlplane.AlertFilter{SubjectID: "sub_alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("subject filter = %d rows, want 2", len(got))
	}

	// By minimum risk (>= 0.9 → alice-0.95 and bob-0.99).
	got, _ = srv.SearchPeerAlerts(ctx, controlplane.AlertFilter{MinRisk: 0.9})
	if len(got) != 2 {
		t.Errorf("min-risk filter = %d rows, want 2", len(got))
	}
	for _, a := range got {
		if a.RiskScore < 0.9 {
			t.Errorf("min-risk returned a %v alert", a.RiskScore)
		}
	}

	// Combined subject + min risk (alice ≥ 0.9 → just the 0.95).
	got, _ = srv.SearchPeerAlerts(ctx, controlplane.AlertFilter{SubjectID: "sub_alice", MinRisk: 0.9})
	if len(got) != 1 || got[0].RiskScore < 0.9 {
		t.Errorf("combined filter = %+v, want the single high-risk alice alert", got)
	}

	// Time window: only the last 45 minutes (bob-30m and alice-10m, not alice-1h/carol-2h).
	got, _ = srv.SearchPeerAlerts(ctx, controlplane.AlertFilter{Since: base.Add(-45 * time.Minute)})
	if len(got) != 2 {
		t.Errorf("since filter = %d rows, want 2 (within 45m)", len(got))
	}

	// SQL-injection-shaped subject is DATA, not SQL: it simply matches nothing, and the
	// table is intact afterward (a concatenated query would error or drop rows).
	inj := `sub_alice'; DROP TABLE peer_alerts; --`
	got, err = srv.SearchPeerAlerts(ctx, controlplane.AlertFilter{SubjectID: inj})
	if err != nil {
		t.Fatalf("injection-shaped subject errored (should be treated as data): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("injection subject matched %d rows, want 0", len(got))
	}
	// The table still exists and still has all four rows.
	all, err := srv.SearchPeerAlerts(ctx, controlplane.AlertFilter{})
	if err != nil || len(all) != 4 {
		t.Fatalf("after injection attempt: %d rows / err %v, want 4 (table intact)", len(all), err)
	}
}
