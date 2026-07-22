package controlplane_test

import (
	"context"
	"testing"

	"github.com/nats-io/nats.go"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// TestIngestRejectsSubjectlessEvent (R34-12, test proposal #2): a signed, correctly
// verified event that carries NO pseudonymous subject must be REJECTED at ingest —
// the subject contract (XDR-3) is enforced server-side, not only in the endpoint's
// engine.attribute. A legacy or rogue agent must not be able to ship subject-less
// events straight into fleet_telemetry.
//
// This drives the REAL path: a genuinely enrolled agent signs the envelope (so it
// PASSES signature/enrollment verification), and the ONLY reason it is rejected is
// the missing subject. Mutation: dropping the subject check in handleSigned makes
// this event persist, so the len==0 / RejectedTelemetry assertions FAIL.
func TestIngestRejectsSubjectlessEvent(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// A fully enrolled agent: its signature WILL verify, so verification is not what
	// rejects the event — the missing subject is.
	pub := signedAgent(t, srv, conn, "agent-nosubj")
	before := srv.RejectedTelemetry.Load()

	// Publish an event with NO subject. The signed publisher signs it, the server
	// verifies the signature, then the ingest-side subject check must reject it.
	if err := pub.PublishEvent(context.Background(), &corev1.Event{
		EventId: "ns-1", AgentId: "agent-nosubj", // no Subject
	}); err != nil {
		t.Fatal(err)
	}

	// The rejection is COUNTED (observable, not a silent vanish).
	waitFor(t, func() bool { return srv.RejectedTelemetry.Load() > before })
	if srv.RejectedTelemetry.Load() <= before {
		t.Fatalf("a subject-less event was not counted as rejected (before=%d now=%d)",
			before, srv.RejectedTelemetry.Load())
	}
	// And it was NEVER stored.
	rows, _ := srv.TelemetryForEvent(context.Background(), "ns-1")
	if len(rows) != 0 {
		t.Fatalf("subject-less event ns-1 was stored (%d rows) — the ingest subject contract is not enforced", len(rows))
	}

	// Positive control: the SAME agent, same path, WITH a subject persists — proving
	// the rejection is the missing subject, not a broken transport.
	if err := pub.PublishEvent(context.Background(), &corev1.Event{
		EventId: "ns-2", AgentId: "agent-nosubj",
		Subject: &corev1.Subject{PseudonymousId: "sub_ok"},
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		r, _ := srv.TelemetryForEvent(context.Background(), "ns-2")
		return len(r) == 1
	})
}
