package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SIEM-11: a legacy alert with an empty agent_id (”) must NOT count as a distinct host, or a
// subject with one real host plus pre-identity alerts would falsely read as cross-host "lateral
// movement". count(DISTINCT NULLIF(agent_id,”)) excludes the empty.
func TestCorrelateIgnoresLegacyEmptyHost(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	seed := func(risk float64, ago time.Duration, host string) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
			 VALUES ('sub_legacy',$1,'v1',$2,$3)`, risk, host, now.Add(-ago)); err != nil {
			t.Fatal(err)
		}
	}
	// One REAL host (agent-a) plus legacy pre-identity alerts ('') — a single true host.
	seed(0.9, 1*time.Minute, "agent-a")
	seed(0.9, 2*time.Minute, "agent-a")
	seed(0.9, 3*time.Minute, "")
	seed(0.9, 4*time.Minute, "")

	// Plain burst (MinHosts=1): raised, and HostCount must be 1 (the empty is not a host).
	got, err := srv.Correlate(ctx, controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("incidents = %d, want 1", len(got))
	}
	if got[0].HostCount != 1 {
		t.Errorf("host count = %d, want 1 — a legacy empty agent_id was counted as a host", got[0].HostCount)
	}

	// Cross-host rule (MinHosts=2): must be EXCLUDED — there is only one real host.
	cross, _ := srv.Correlate(ctx, controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3, MinHosts: 2}, now)
	for _, inc := range cross {
		if inc.SubjectID == "sub_legacy" {
			t.Error("a single-real-host subject with legacy '' alerts falsely reached MinHosts=2 (false lateral movement)")
		}
	}
}
