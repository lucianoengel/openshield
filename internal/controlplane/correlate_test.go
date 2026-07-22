package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// F2: a burst of alerts for one subject within the window correlates into an incident;
// a subject below the count threshold, or with alerts outside the window / below the risk
// floor, does not.
func TestCorrelateBurst(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	seed := func(subject string, risk float64, ago time.Duration, host string) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
			 VALUES ($1,$2,'v1',$3,$4)`, subject, risk, host, now.Add(-ago)); err != nil {
			t.Fatal(err)
		}
	}

	// sub_burst: 4 alerts in the last 20 minutes → an incident (>= 3), all on ONE host.
	seed("sub_burst", 0.9, 1*time.Minute, "agent-a")
	seed("sub_burst", 0.95, 5*time.Minute, "agent-a")
	seed("sub_burst", 0.8, 12*time.Minute, "agent-a")
	seed("sub_burst", 0.99, 18*time.Minute, "agent-a")
	// sub_quiet: only 1 alert → not an incident.
	seed("sub_quiet", 0.97, 3*time.Minute, "agent-a")
	// sub_old: 4 alerts but all OUTSIDE a 30m window → not an incident within window.
	for i := 0; i < 4; i++ {
		seed("sub_old", 0.9, 2*time.Hour+time.Duration(i)*time.Minute, "agent-a")
	}
	// sub_lateral: a burst SPANNING three agents — the cross-host signal.
	seed("sub_lateral", 0.85, 2*time.Minute, "agent-a")
	seed("sub_lateral", 0.88, 6*time.Minute, "agent-b")
	seed("sub_lateral", 0.91, 10*time.Minute, "agent-c")

	rule := controlplane.CorrelationRule{Window: 30 * time.Minute, MinAlerts: 3}
	incidents, err := srv.Correlate(ctx, rule, now)
	if err != nil {
		t.Fatal(err)
	}
	// Both sub_burst and sub_lateral qualify on the plain burst rule (>= 3 in-window).
	bySubject := map[string]controlplane.Incident{}
	for _, i := range incidents {
		bySubject[i.SubjectID] = i
	}
	inc, ok := bySubject["sub_burst"]
	if !ok {
		t.Fatalf("sub_burst not correlated; got %+v", incidents)
	}
	if inc.AlertCount != 4 {
		t.Errorf("alert count = %d, want 4", inc.AlertCount)
	}
	if inc.MaxRisk < 0.98 {
		t.Errorf("max risk = %v, want the 0.99 peak", inc.MaxRisk)
	}
	if inc.HostCount != 1 {
		t.Errorf("sub_burst host count = %d, want 1 (single-agent burst)", inc.HostCount)
	}
	if !inc.LastSeen.After(inc.FirstSeen) {
		t.Errorf("last seen %v not after first seen %v", inc.LastSeen, inc.FirstSeen)
	}
	if lat := bySubject["sub_lateral"]; lat.HostCount != 3 {
		t.Errorf("sub_lateral host count = %d, want 3 (three agents)", lat.HostCount)
	}

	// Cross-host rule (MinHosts=2): only sub_lateral qualifies — sub_burst's 4 alerts are all
	// one agent. This is the facet the distinct-host count exists for; if it were a constant 1,
	// nothing would match and this would fail.
	cross := controlplane.CorrelationRule{Window: 30 * time.Minute, MinAlerts: 3, MinHosts: 2}
	got, err := srv.Correlate(ctx, cross, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SubjectID != "sub_lateral" {
		t.Fatalf("cross-host rule (min_hosts=2) = %+v, want only sub_lateral", got)
	}
	if got[0].HostCount != 3 {
		t.Errorf("sub_lateral cross-host count = %d, want 3", got[0].HostCount)
	}

	// Raising the risk floor above the burst's lowest alert drops it below the count
	// threshold (only 3 of the 4 are >= 0.9), so it is no longer an incident.
	strict := controlplane.CorrelationRule{Window: 30 * time.Minute, MinAlerts: 4, MinRisk: 0.9}
	strictGot, _ := srv.Correlate(ctx, strict, now)
	for _, i := range strictGot {
		if i.SubjectID == "sub_burst" {
			t.Errorf("with min_risk 0.9 and min_alerts 4, sub_burst has only 3 qualifying alerts: got %+v", strictGot)
		}
	}
}
