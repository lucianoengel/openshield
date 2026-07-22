package controlplane_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SIEM-11b: correlated incidents are materialized with a stable id + state (one OPEN per subject; a
// re-correlated burst updates it, not duplicates), can be acknowledged as a unit (first-ack-wins),
// and a DB failure during ack is not "not found".
func TestMaterializeAndAcknowledgeIncident(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	seed := func(risk float64, ago time.Duration, host string) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
			 VALUES ('sub_inc',$1,'v1',$2,$3)`, risk, host, now.Add(-ago)); err != nil {
			t.Fatal(err)
		}
	}
	seed(0.9, 1*time.Minute, "agent-a")
	seed(0.95, 5*time.Minute, "agent-a")
	seed(0.8, 10*time.Minute, "agent-a")

	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}
	n, err := srv.MaterializeIncidents(ctx, rule, now)
	if err != nil || n != 1 {
		t.Fatalf("materialize = %d, %v; want 1", n, err)
	}

	// Re-materializing (a new burst) UPDATES the open incident — no duplicate.
	seed(0.99, 30*time.Second, "agent-a")
	if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
		t.Fatal(err)
	}
	stored, err := srv.RecentIncidents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	open := 0
	var inc controlplane.StoredIncident
	for _, s := range stored {
		if s.SubjectID == "sub_inc" && s.State == "open" {
			open++
			inc = s
		}
	}
	if open != 1 {
		t.Fatalf("open incidents for sub_inc = %d, want exactly 1 (re-correlation must not duplicate)", open)
	}
	if inc.AlertCount != 4 || inc.MaxRisk < 0.98 || inc.Severity != controlplane.SeverityCritical {
		t.Errorf("incident not refreshed on re-materialize: %+v", inc)
	}

	// Acknowledge the incident as a unit; first-ack-wins.
	newly, err := srv.AcknowledgeIncident(ctx, inc.ID, "operator:alice")
	if err != nil || !newly {
		t.Fatalf("first ack = %v, %v; want true", newly, err)
	}
	newly2, _ := srv.AcknowledgeIncident(ctx, inc.ID, "operator:bob")
	if newly2 {
		t.Error("second ack reported newly — first-ack-wins violated")
	}

	// After ack, a fresh burst can open a NEW incident (the partial unique index is per open state).
	if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
		t.Fatal(err)
	}
	stored2, _ := srv.RecentIncidents(ctx, 100)
	var openAfter, acked int
	for _, s := range stored2 {
		if s.SubjectID != "sub_inc" {
			continue
		}
		if s.State == "open" {
			openAfter++
		} else if s.State == "acknowledged" {
			acked++
		}
	}
	if acked != 1 || openAfter != 1 {
		t.Errorf("after ack+re-materialize: acked=%d open=%d, want 1 and 1 (a new open incident opens post-ack)", acked, openAfter)
	}

	// A phantom id errors; a DB failure is not "not found".
	if _, err := srv.AcknowledgeIncident(ctx, 9_999_999, "operator:alice"); !errors.Is(err, controlplane.ErrIncidentNotFound) {
		t.Errorf("phantom ack = %v, want ErrIncidentNotFound", err)
	}
	pool.Close()
	if _, err := srv.AcknowledgeIncident(context.Background(), inc.ID, "operator:alice"); err == nil || errors.Is(err, controlplane.ErrIncidentNotFound) {
		t.Errorf("ack against a closed pool = %v, want a real error (not ErrIncidentNotFound)", err)
	}
}
