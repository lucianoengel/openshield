package controlplane_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/pseudonym"
	"github.com/lucianoengel/openshield/internal/xdr"
)

// deviceAliasID reads the entity id for a device alias directly from the graph tables — a READ-ONLY
// lookup (Resolve is find-or-create, which would fabricate the row), so it distinguishes "a producer
// resolved this device" from "my assertion just created it". Returns (0,false) when no alias exists.
func deviceAliasID(pool *pgxpool.Pool, subject string) (int64, bool) {
	var id int64
	err := pool.QueryRow(context.Background(),
		`SELECT entity_id FROM entity_aliases WHERE kind=$1 AND value=$2`, xdr.KindDevice, subject).Scan(&id)
	if err != nil {
		return 0, false
	}
	return id, true
}

// TestIngestPopulatesDeviceEntity (XDR-1-WIRE, test #1 — ingest producer): a VERIFIED event flowing
// through the real signed transport → handleSigned must populate a device entity for the event's
// canonical subject. Uses a NOVEL subject that enrollment never touched, so the read-only alias check
// isolates INGEST as the producer.
//
// Mutation: removing the resolveDeviceEntity call in handleSigned leaves no alias for the novel
// subject → deviceAliasID returns false → FAIL.
func TestIngestPopulatesDeviceEntity(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pub := signedAgent(t, srv, conn, "agent-xdr-ingest")
	pool := mustPoolCP(t)
	defer pool.Close()

	// Unique per run: the entity graph persists across test runs (the CP reset does not drop it), so a
	// fixed subject would already exist on a re-run and the read-only isolation would break. A fresh
	// subject each run guarantees ingest is the SOLE creator.
	novelSubject := fmt.Sprintf("sub_xdr_novel_%d", time.Now().UnixNano())
	eventID := fmt.Sprintf("xdr-ev-1-%d", time.Now().UnixNano())
	if _, ok := deviceAliasID(pool, novelSubject); ok {
		t.Fatal("precondition: the novel subject already has a device entity")
	}
	if err := pub.PublishEvent(context.Background(), &corev1.Event{
		EventId: eventID, AgentId: "agent-xdr-ingest",
		Subject: &corev1.Subject{PseudonymousId: novelSubject},
	}); err != nil {
		t.Fatal(err)
	}
	// The event persists (proving it was ingested), then the device entity must exist for its subject.
	waitFor(t, func() bool {
		rows, _ := srv.TelemetryForEvent(context.Background(), eventID)
		return len(rows) == 1
	})
	waitFor(t, func() bool { _, ok := deviceAliasID(pool, novelSubject); return ok })
	if _, ok := deviceAliasID(pool, novelSubject); !ok {
		t.Fatal("ingest did not populate the device entity for the verified event's subject (XDR-1-WIRE)")
	}
}

// TestEnrollAndIngestConvergeOnOneEntity (XDR-1-WIRE, test #1 — kills the TestCanonicalJoin tautology):
// enrollment and telemetry ingest are TWO independent real producers; a device referenced by both must
// resolve to ONE entity id, proven through the real Enroll + real signed ingest paths — not two in-test
// pseudonym.Of calls.
func TestEnrollAndIngestConvergeOnOneEntity(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	const agentID = "agent-xdr-converge"
	subject := pseudonym.Of(agentID) // the canonical device id both producers key on (IDENT-1/XDR-3)
	pool := mustPoolCP(t)
	defer pool.Close()

	// Producer 1: real enrollment resolves the device entity.
	pub := signedAgent(t, srv, conn, agentID)
	var enrolledID int64
	waitFor(t, func() bool { id, ok := deviceAliasID(pool, subject); enrolledID = id; return ok })
	if enrolledID == 0 {
		t.Fatal("enrollment did not populate the device entity")
	}

	// Producer 2: real signed ingest of an event carrying the same canonical subject.
	if err := pub.PublishEvent(context.Background(), &corev1.Event{
		EventId: "xdr-ev-2", AgentId: agentID,
		Subject: &corev1.Subject{PseudonymousId: subject},
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		rows, _ := srv.TelemetryForEvent(context.Background(), "xdr-ev-2")
		return len(rows) == 1
	})

	// They converge: the same single entity id, not two.
	ingestID, ok := deviceAliasID(pool, subject)
	if !ok {
		t.Fatal("the device entity vanished after ingest")
	}
	if ingestID != enrolledID {
		t.Fatalf("two real producers diverged: enrollment id %d != ingest id %d — the entity graph is not coalescing the device", enrolledID, ingestID)
	}
	if srv.EntityResolveFailures.Load() != 0 {
		t.Errorf("entity resolve failures = %d, want 0", srv.EntityResolveFailures.Load())
	}
}

// TestIngestGraphFailureDoesNotBreakIngest (XDR-1-WIRE, best-effort contract): if the entity-graph
// write fails, a verified event is STILL persisted and the failure is COUNTED, never surfaced. The
// failure is forced by installing a graph over a CLOSED pool — no shared-schema mutation, so the test
// cannot corrupt the database for concurrent/subsequent tests.
func TestIngestGraphFailureDoesNotBreakIngest(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pub := signedAgent(t, srv, conn, "agent-xdr-fail")

	// Break the graph write path (not verification/persist): a store over a closed pool fails every
	// Resolve, without touching the shared schema.
	brokenPool := mustPoolCP(t)
	brokenPool.Close()
	srv.SetEntityGraph(xdr.NewStore(brokenPool))

	before := srv.EntityResolveFailures.Load()
	if err := pub.PublishEvent(context.Background(), &corev1.Event{
		EventId: "xdr-ev-3", AgentId: "agent-xdr-fail",
		Subject: &corev1.Subject{PseudonymousId: "sub_xdr_fail"},
	}); err != nil {
		t.Fatal(err)
	}
	// The event still lands (ingest is not broken by the graph failure)...
	waitFor(t, func() bool {
		rows, _ := srv.TelemetryForEvent(context.Background(), "xdr-ev-3")
		return len(rows) == 1
	})
	// ...and the graph failure was counted, not silent.
	waitFor(t, func() bool { return srv.EntityResolveFailures.Load() > before })
	if srv.EntityResolveFailures.Load() <= before {
		t.Fatal("a graph write failure was not counted (best-effort must still be observable)")
	}
}
