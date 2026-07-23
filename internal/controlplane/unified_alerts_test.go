package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/xdr"
)

// TestPeerAlertProjectsToEntityKeyedUnifiedAlert (XDR-2): the REAL server-side peer-UEBA path, on a
// verified outlier, records a unified alert whose entity_id equals the SAME entity the device graph
// resolved for that subject — the alert⋈device-entity join, not a tautology. And a second domain's
// alert for the same subject shares that one entity (the cross-domain grouping XDR-4 reads).
//
// Mutation: if RecordUnifiedAlert stored the subject instead of resolving the entity, AlertsForEntity
// (queried by entity id) would return nothing → the assertions FAIL.
func TestPeerAlertProjectsToEntityKeyedUnifiedAlert(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServerPeer(t, url, 0.5, time.Hour)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pub := signedAgent(t, srv, conn, "agent-xdr2")
	ctx := context.Background()

	const outlier = "sub_xdr2_outlier"
	for _, sub := range []string{"p1", "p2", "p3"} {
		for i := 0; i < 3; i++ {
			if err := pub.PublishEvent(ctx, eventFor("e", sub)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := 0; i < 40; i++ {
		if err := pub.PublishEvent(ctx, eventFor("e", outlier)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool { return srv.PeerAlerts.Load() >= 1 })

	// The device entity the graph resolved for the outlier subject (ingest created it, D203).
	pool := mustPoolCP(t)
	defer pool.Close()
	var entityID int64
	waitFor(t, func() bool {
		err := pool.QueryRow(ctx, `SELECT entity_id FROM entity_aliases WHERE kind=$1 AND value=$2`,
			xdr.KindDevice, outlier).Scan(&entityID)
		return err == nil && entityID != 0
	})

	// The peer-UEBA alert is projected into the unified stream, keyed to THAT entity.
	waitFor(t, func() bool {
		alerts, _ := srv.AlertsForEntity(ctx, entityID)
		for _, a := range alerts {
			if a.Domain == "ueba" && a.SubjectID == outlier {
				return true
			}
		}
		return false
	})
	if srv.UnifiedAlertFailures.Load() != 0 {
		t.Errorf("unified alert failures = %d, want 0", srv.UnifiedAlertFailures.Load())
	}

	// A SECOND domain's alert for the same subject resolves to the SAME entity → both group under it.
	if err := srv.RecordUnifiedAlert(ctx, "dlp", xdr.KindDevice, outlier, "high", "sensitive exfil", "dlp:"+outlier, time.Now()); err != nil {
		t.Fatalf("record dlp unified alert: %v", err)
	}
	alerts, err := srv.AlertsForEntity(ctx, entityID)
	if err != nil {
		t.Fatal(err)
	}
	domains := map[string]bool{}
	for _, a := range alerts {
		if a.EntityID != entityID {
			t.Errorf("an alert has entity_id %d, want %d", a.EntityID, entityID)
		}
		domains[a.Domain] = true
	}
	if !domains["ueba"] || !domains["dlp"] {
		t.Fatalf("AlertsForEntity(%d) domains = %v, want both ueba and dlp sharing the entity", entityID, domains)
	}
}

// TestUnifiedAlertDedupes (XDR-2): the same logical alert (same dedup_key) is one row, so a re-detection
// does not multiply correlation input.
//
// Mutation: dropping ON CONFLICT (dedup_key) DO NOTHING → the second insert errors or duplicates → this
// FAILs.
func TestUnifiedAlertDedupes(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool) // New() builds the entity graph from the pool (D203)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if err := srv.RecordUnifiedAlert(ctx, "hips", xdr.KindDevice, "sub_dedup", "high", "process kill", "hips-kill:sub_dedup:42", time.Now()); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	var entityID int64
	if err := pool.QueryRow(ctx, `SELECT entity_id FROM entity_aliases WHERE kind=$1 AND value=$2`,
		xdr.KindDevice, "sub_dedup").Scan(&entityID); err != nil {
		t.Fatal(err)
	}
	alerts, err := srv.AlertsForEntity(ctx, entityID)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range alerts {
		if a.DedupKey == "hips-kill:sub_dedup:42" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("same dedup_key recorded twice yielded %d rows, want 1", n)
	}
}
