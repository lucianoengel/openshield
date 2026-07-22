package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SIEM-6b/ADR-10: the peer-alert write path stamps the first-class lifecycle fields — a stored
// severity (from the risk), status 'open', and a detector-namespaced dedup/correlation key — and
// acknowledgement advances the status beyond 'open'.
func TestPeerAlertLifecycleFields(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `DELETE FROM peer_alerts`); err != nil {
		t.Fatal(err)
	}
	srv := controlplane.New(pool)

	if err := controlplane.RecordPeerAlertForTest(srv, ctx, "sub_x", 0.80, "v1", "agent-a", time.Now()); err != nil {
		t.Fatalf("recordPeerAlert: %v", err)
	}

	alerts, err := srv.RecentPeerAlerts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	var got controlplane.PeerAlert
	for _, a := range alerts {
		if a.SubjectID == "sub_x" {
			got = a
		}
	}
	if got.ID == 0 {
		t.Fatal("the recorded alert was not read back")
	}
	if got.Severity != controlplane.SeverityHigh {
		t.Errorf("stored severity = %q, want high (risk 0.80 stamped at write)", got.Severity)
	}
	if got.Status != "open" {
		t.Errorf("status = %q, want open", got.Status)
	}
	if got.DedupKey != "peer-ueba:sub_x" {
		t.Errorf("dedup_key = %q, want peer-ueba:sub_x", got.DedupKey)
	}

	// Acknowledgement advances the status beyond open.
	newly, err := srv.AcknowledgeAlert(ctx, got.ID, "operator:alice")
	if err != nil || !newly {
		t.Fatalf("acknowledge: newly=%v err=%v", newly, err)
	}
	after, err := srv.RecentPeerAlerts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range after {
		if a.ID == got.ID {
			if a.Status != "triaged" {
				t.Errorf("after ack, status = %q, want triaged (the lifecycle advanced)", a.Status)
			}
			if a.AcknowledgedBy != "operator:alice" {
				t.Errorf("acknowledged_by = %q, want operator:alice", a.AcknowledgedBy)
			}
		}
	}
}
