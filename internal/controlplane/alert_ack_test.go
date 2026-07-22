package controlplane_test

import (
	"context"
	"errors"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SIEM-6: acknowledging an alert is first-ack-wins and operator-attributed. A second ack is a
// no-op that preserves the original triager; acking a phantom id is an error, not a silent no-op;
// and the unacknowledged filter is the actionable queue.
func TestAcknowledgeAlert(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	var id int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id)
		 VALUES ('sub_ack', 0.92, 'v1', 'agent-a') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	// A second, lower-risk alert left UNacknowledged, to prove the queue filter.
	if _, err := pool.Exec(ctx,
		`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id)
		 VALUES ('sub_open', 0.80, 'v1', 'agent-a')`); err != nil {
		t.Fatal(err)
	}

	// First ack wins.
	newly, err := srv.AcknowledgeAlert(ctx, id, "operator:alice")
	if err != nil {
		t.Fatal(err)
	}
	if !newly {
		t.Error("first ack reported newlyAcked=false")
	}

	// Second ack is a no-op that preserves alice as the original triager.
	newly2, err := srv.AcknowledgeAlert(ctx, id, "operator:bob")
	if err != nil {
		t.Fatal(err)
	}
	if newly2 {
		t.Error("second ack reported newlyAcked=true — first-ack-wins violated")
	}
	var by string
	if err := pool.QueryRow(ctx, `SELECT acknowledged_by FROM peer_alerts WHERE id=$1`, id).Scan(&by); err != nil {
		t.Fatal(err)
	}
	if by != "operator:alice" {
		t.Errorf("acknowledged_by = %q, want operator:alice (bob's late ack must not overwrite)", by)
	}

	// Acking a non-existent alert is an error, not a silent no-op.
	if _, err := srv.AcknowledgeAlert(ctx, 9_999_999, "operator:alice"); !errors.Is(err, controlplane.ErrAlertNotFound) {
		t.Errorf("ack of a phantom id = %v, want ErrAlertNotFound", err)
	}

	// The unacknowledged filter is the actionable queue: only sub_open remains.
	open, err := srv.SearchPeerAlerts(ctx, controlplane.AlertFilter{UnacknowledgedOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range open {
		if a.SubjectID == "sub_ack" {
			t.Errorf("acknowledged alert sub_ack still in the unacknowledged queue")
		}
	}
	sawOpen := false
	for _, a := range open {
		if a.SubjectID == "sub_open" {
			sawOpen = true
			if a.Severity != controlplane.SeverityHigh {
				t.Errorf("sub_open severity = %q, want high (risk 0.80)", a.Severity)
			}
		}
	}
	if !sawOpen {
		t.Error("sub_open (unacknowledged) missing from the queue")
	}

	// min_severity=critical excludes the 0.80 (high) alert.
	crit, err := srv.SearchPeerAlerts(ctx, controlplane.AlertFilter{MinSeverity: controlplane.SeverityCritical})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range crit {
		if a.SubjectID == "sub_open" {
			t.Errorf("min_severity=critical returned a high (0.80) alert")
		}
	}
}
