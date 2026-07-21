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

	seed := func(subject string, risk float64, ago time.Duration) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, detected_at)
			 VALUES ($1,$2,'v1',$3)`, subject, risk, now.Add(-ago)); err != nil {
			t.Fatal(err)
		}
	}

	// sub_burst: 4 alerts in the last 20 minutes → an incident (>= 3).
	seed("sub_burst", 0.9, 1*time.Minute)
	seed("sub_burst", 0.95, 5*time.Minute)
	seed("sub_burst", 0.8, 12*time.Minute)
	seed("sub_burst", 0.99, 18*time.Minute)
	// sub_quiet: only 1 alert → not an incident.
	seed("sub_quiet", 0.97, 3*time.Minute)
	// sub_old: 4 alerts but all OUTSIDE a 30m window → not an incident within window.
	for i := 0; i < 4; i++ {
		seed("sub_old", 0.9, 2*time.Hour+time.Duration(i)*time.Minute)
	}

	rule := controlplane.CorrelationRule{Window: 30 * time.Minute, MinAlerts: 3}
	incidents, err := srv.Correlate(ctx, rule, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 1 {
		t.Fatalf("incidents = %d, want 1 (only sub_burst)", len(incidents))
	}
	inc := incidents[0]
	if inc.SubjectID != "sub_burst" {
		t.Errorf("incident subject = %q, want sub_burst", inc.SubjectID)
	}
	if inc.AlertCount != 4 {
		t.Errorf("alert count = %d, want 4", inc.AlertCount)
	}
	if inc.MaxRisk < 0.98 {
		t.Errorf("max risk = %v, want the 0.99 peak", inc.MaxRisk)
	}
	if !inc.LastSeen.After(inc.FirstSeen) {
		t.Errorf("last seen %v not after first seen %v", inc.LastSeen, inc.FirstSeen)
	}

	// Raising the risk floor above the burst's lowest alert drops it below the count
	// threshold (only 3 of the 4 are >= 0.9), so it is no longer an incident.
	strict := controlplane.CorrelationRule{Window: 30 * time.Minute, MinAlerts: 4, MinRisk: 0.9}
	got, _ := srv.Correlate(ctx, strict, now)
	if len(got) != 0 {
		t.Errorf("with min_risk 0.9 and min_alerts 4, sub_burst has only 3 qualifying alerts: got %+v", got)
	}
}
