package nats_test

import (
	"context"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// TestJetStreamEnabledIsOnByDefault walks every input the gate can see. Durable ingest is the default, an
// explicit falsy value opts out, and an UNRECOGNIZED value stays ENABLED — a typo must not quietly turn off
// the durability a deployer believes they have.
//
// Mutation: revert the gate to opt-in (`!= ""`) → the unset case FAILS.
func TestJetStreamEnabledIsOnByDefault(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
		note string
	}{
		{"", true, "unset = durable by default"},
		{"0", false, "explicit opt-out"},
		{"false", false, "explicit opt-out"},
		{"FALSE", false, "case-insensitive opt-out"},
		{"off", false, "explicit opt-out"},
		{"no", false, "explicit opt-out"},
		{" off ", false, "whitespace-tolerant opt-out"},
		{"1", true, "explicitly on"},
		{"true", true, "explicitly on"},
		{"maybe", true, "an unrecognized value must NOT silently disable durability"},
	} {
		t.Setenv("OPENSHIELD_JETSTREAM", tc.val)
		if got := natsx.JetStreamEnabled(); got != tc.want {
			t.Errorf("OPENSHIELD_JETSTREAM=%q → %v, want %v (%s)", tc.val, got, tc.want, tc.note)
		}
	}
}

// jsBroker starts an embedded NATS with JetStream ENABLED.
func jsBroker(t *testing.T) string {
	t.Helper()
	opts := &natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("embedded JetStream broker did not become ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv.ClientURL()
}

// coreOnlyBroker starts an embedded NATS with JetStream DISABLED — the deployment shape that must fail fast.
func coreOnlyBroker(t *testing.T) string {
	t.Helper()
	opts := &natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: false}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("embedded core-only broker did not become ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv.ClientURL()
}

func testPublisher(t *testing.T, url, agentID string) (*natsx.SignedPublisher, *nats.Conn) {
	t.Helper()
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	id, err := identity.Generate(agentID)
	if err != nil {
		t.Fatal(err)
	}
	return natsx.NewSignedPublisher(agentID, id, conn), conn
}

// TestProducerPublishesIntoTheStreamByDefault is the test that pins the bug this ticket fixed: a producer
// that builds a signed publisher and forgets the durable switch publishes at-most-once while the platform
// claims durable ingest. It asserts at the SEAM — a JetStream consumer receives the message — which is only
// true if the publisher took the durable branch.
//
// Mutation: remove the EnableDurableIfDefault call → the stream consumer receives nothing → this FAILS.
func TestProducerPublishesIntoTheStreamByDefault(t *testing.T) {
	t.Setenv("OPENSHIELD_JETSTREAM", "") // no override: the DEFAULT path is under test
	url := jsBroker(t)
	pub, conn := testPublisher(t, url, "agent-plat2-default")

	if err := natsx.EnableDurableIfDefault(pub); err != nil {
		t.Fatalf("enabling durable ingest on a JetStream broker: %v", err)
	}
	if err := pub.PublishEvent(context.Background(), &corev1.Event{
		EventId: "plat2-e1", AgentId: "agent-plat2-default",
		Subject: &corev1.Subject{PseudonymousId: "sub_plat2"},
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Read it back from the STREAM (not a core subscription): proof the message is durably stored.
	js, err := conn.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	sub, err := js.PullSubscribe(natsx.SubjectSigned, "plat2-verify", nats.BindStream(natsx.TelemetryStream))
	if err != nil {
		t.Fatalf("pull-subscribing to the telemetry stream: %v", err)
	}
	msgs, err := sub.Fetch(1, nats.MaxWait(3*time.Second))
	if err != nil {
		t.Fatalf("no message in the stream — the publisher did not take the durable path: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("fetched %d messages, want 1", len(msgs))
	}
	_ = msgs[0].Ack()
}

// TestOptOutUsesCoreNATS: the escape hatch must genuinely work on a broker without JetStream, or a
// deployment that cannot run JetStream has no way forward.
func TestOptOutUsesCoreNATS(t *testing.T) {
	t.Setenv("OPENSHIELD_JETSTREAM", "0")
	url := coreOnlyBroker(t)
	pub, conn := testPublisher(t, url, "agent-plat2-optout")

	if err := natsx.EnableDurableIfDefault(pub); err != nil {
		t.Fatalf("the opt-out must be a no-op, got: %v", err)
	}
	// A core subscriber receives it — no stream required.
	got := make(chan struct{}, 1)
	if _, err := conn.Subscribe(natsx.SubjectSigned, func(*nats.Msg) { got <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	if err := pub.PublishEvent(context.Background(), &corev1.Event{EventId: "plat2-core"}); err != nil {
		t.Fatalf("publish over core NATS: %v", err)
	}
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("the opted-out publisher's message never arrived over core NATS")
	}
}

// TestUnavailableJetStreamFailsFast: a broker without JetStream must stop the producer with an actionable
// error, NOT degrade to at-most-once.
//
// Mutation: swallow the error and continue on core NATS → this FAILS. That mutation is the tempting one —
// it keeps every deployment starting — and it is precisely what leaves an operator believing telemetry is
// durable while it is not.
func TestUnavailableJetStreamFailsFast(t *testing.T) {
	t.Setenv("OPENSHIELD_JETSTREAM", "") // default mode, but the broker cannot serve it
	url := coreOnlyBroker(t)
	pub, _ := testPublisher(t, url, "agent-plat2-nojs")

	err := natsx.EnableDurableIfDefault(pub)
	if err == nil {
		t.Fatal("a broker without JetStream did not fail the producer — it would have run at-most-once " +
			"while claiming durable ingest")
	}
	if !strings.Contains(err.Error(), "OPENSHIELD_JETSTREAM") {
		t.Errorf("the error must name the opt-out so an operator can act on it; got: %v", err)
	}
}
