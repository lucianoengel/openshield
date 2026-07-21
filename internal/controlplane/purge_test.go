package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// PurgeOlderThan hard-deletes fleet_telemetry + peer_alerts older than the cutoff and
// keeps rows newer than it — the enforced retention window (D81).
func TestPurgeOlderThanEnforcesWindow(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	old := time.Now().Add(-100 * 24 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)

	// Two telemetry rows (old + recent) and two peer alerts (old + recent).
	if _, err := pool.Exec(ctx,
		`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload, received_at) VALUES
		 ('a','event','old', '\x00', $1), ('a','event','new', '\x00', $2)`, old, recent); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO peer_alerts (subject_id, risk_score, context_version, detected_at) VALUES
		 ('s', 0.9, '', $1), ('s', 0.9, '', $2)`, old, recent); err != nil {
		t.Fatal(err)
	}

	cutoff := time.Now().Add(-30 * 24 * time.Hour) // between old and recent
	n, err := srv.PurgeOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("purged %d rows, want 2 (one old telemetry + one old peer alert)", n)
	}

	if got := count(t, pool, "SELECT count(*) FROM fleet_telemetry"); got != 1 {
		t.Errorf("fleet_telemetry has %d rows, want 1 (the recent one kept)", got)
	}
	if got := count(t, pool, "SELECT count(*) FROM peer_alerts"); got != 1 {
		t.Errorf("peer_alerts has %d rows, want 1 (the recent one kept)", got)
	}
	// The surviving rows are the recent ones.
	if got := count(t, pool, "SELECT count(*) FROM fleet_telemetry WHERE event_id='new'"); got != 1 {
		t.Error("the recent telemetry row was purged — the window kept the wrong rows")
	}
}

func count(t *testing.T, pool *pgxpool.Pool, sql string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
