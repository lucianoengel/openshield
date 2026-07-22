package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// TestJetStreamRedeliversOnDBFailure (R34-4, test proposal #6): a verified message whose
// PERSIST fails transiently (the DB rejects the insert) must be Nak'd and REDELIVERED, never
// Ack'd-and-lost. We force the transient failure with a surgical CHECK(false) constraint on
// fleet_telemetry — verification still succeeds (agent_identities is intact), only the insert
// fails — then lift the constraint and prove the message finally persists.
//
// The mutation R34-4 named is exactly what this kills: change NakWithDelay(...) to Ack(). With
// an Ack, the first transient failure removes the message from the stream, so lifting the
// constraint never persists it and the final assertion FAILS.
func TestJetStreamRedeliversOnDBFailure(t *testing.T) {
	t.Setenv("OPENSHIELD_JETSTREAM", "1")
	pool := requireDB(t)
	url := embeddedNATS(t)

	srv := controlplane.New(pool)
	ctx := context.Background()
	tok, err := srv.IssueToken(ctx, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Generate("agent-dbfail")
	if err := srv.Enroll(ctx, tok, "agent-dbfail", id.PublicKey(), time.Now()); err != nil {
		t.Fatal(err)
	}

	// Break inserts (but not verification): a NOT VALID CHECK(false) fails every new row while
	// leaving existing rows and other tables untouched.
	if _, err := pool.Exec(ctx, `ALTER TABLE fleet_telemetry ADD CONSTRAINT r34_block CHECK (false) NOT VALID`); err != nil {
		t.Fatalf("install block constraint: %v", err)
	}

	// Publish one signed event over the durable JetStream producer.
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pub := natsx.NewSignedPublisher("agent-dbfail", id, conn)
	if err := pub.UseJetStream(); err != nil {
		t.Fatalf("UseJetStream: %v", err)
	}
	if err := pub.PublishEvent(ctx, &corev1.Event{
		EventId: "dbfail-1", AgentId: "agent-dbfail",
		Subject: &corev1.Subject{PseudonymousId: "sub_dbfail"},
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Start the durable consumer. Delivery → insert blocked → transient → Nak+backoff → redeliver.
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.Run(rctx, url) }()

	// The message is delivered and FAILS to persist at least once (counted, not silently dropped),
	// and is NOT yet stored.
	waitFor(t, func() bool { return srv.DecodeFailures.Load() >= 1 })
	if rows, _ := srv.TelemetryForEvent(ctx, "dbfail-1"); len(rows) != 0 {
		t.Fatalf("event persisted while the DB was blocking inserts (%d rows)", len(rows))
	}

	// Heal the DB. A redelivery (the message was Nak'd, not Ack'd) now persists it — proving the
	// verified message was retained across the transient failure.
	if _, err := pool.Exec(ctx, `ALTER TABLE fleet_telemetry DROP CONSTRAINT r34_block`); err != nil {
		t.Fatalf("drop block constraint: %v", err)
	}
	waitFor(t, func() bool {
		rows, _ := srv.TelemetryForEvent(ctx, "dbfail-1")
		return len(rows) == 1
	})
}

// TestNakBackoffSchedule (R34-4): the redelivery delay doubles from the base and caps at the max,
// so a sustained outage is retried patiently rather than hot-looped. Pure schedule, no broker.
func TestNakBackoffSchedule(t *testing.T) {
	cases := []struct {
		numDelivered uint64
		want         time.Duration
	}{
		{0, controlplane.NakBackoffBase()},     // never-delivered guard → base
		{1, controlplane.NakBackoffBase()},     // first delivery → base
		{2, 2 * controlplane.NakBackoffBase()}, // doubles
		{3, 4 * controlplane.NakBackoffBase()},
		{100, controlplane.NakBackoffMax()}, // saturates at the cap, never overflows
	}
	for _, c := range cases {
		if got := controlplane.BackoffFor(c.numDelivered); got != c.want {
			t.Errorf("backoffFor(%d) = %v, want %v", c.numDelivered, got, c.want)
		}
	}
	// Monotonic non-decreasing and bounded across the whole range.
	prev := time.Duration(0)
	for n := uint64(1); n <= 64; n++ {
		d := controlplane.BackoffFor(n)
		if d < prev {
			t.Fatalf("backoff decreased at n=%d: %v < %v", n, d, prev)
		}
		if d > controlplane.NakBackoffMax() {
			t.Fatalf("backoff at n=%d exceeded the cap: %v", n, d)
		}
		prev = d
	}
}
