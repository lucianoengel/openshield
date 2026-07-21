package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

func mustPoolCP(t *testing.T) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// enroll an agent on the server and return a SignedPublisher over the connection.
func signedAgent(t *testing.T, srv *controlplane.Server, conn *nats.Conn, agentID string) *natsx.SignedPublisher {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	tok, err := srv.IssueToken(ctx, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate(agentID)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Enroll(ctx, tok, agentID, id.PublicKey(), now); err != nil {
		t.Fatal(err)
	}
	return natsx.NewSignedPublisher(agentID, id, conn)
}

func runServer(t *testing.T, url string) *controlplane.Server {
	t.Helper()
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Run(ctx, url) }()
	time.Sleep(100 * time.Millisecond)
	return srv
}

// An enrolled agent's signed telemetry verifies, is stored verified, attributed.
func TestSignedTelemetryVerified(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pub := signedAgent(t, srv, conn, "agent-signed")

	if err := pub.PublishEvent(context.Background(), &corev1.Event{EventId: "sev-1", AgentId: "agent-signed"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		rows, _ := srv.TelemetryForEvent(context.Background(), "sev-1")
		return len(rows) == 1
	})
	rows, _ := srv.Telemetry(context.Background(), "agent-signed")
	if len(rows) != 1 {
		t.Fatalf("verified telemetry not attributed to the agent: %d rows", len(rows))
	}
	// The stored row is marked verified.
	pool := mustPoolCP(t)
	defer pool.Close()
	var verified bool
	if err := pool.QueryRow(context.Background(),
		`SELECT verified FROM fleet_telemetry WHERE event_id='sev-1'`).Scan(&verified); err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Error("signed, verified telemetry was stored verified=false")
	}
	if srv.RejectedTelemetry.Load() != 0 {
		t.Errorf("a valid message was rejected (%d)", srv.RejectedTelemetry.Load())
	}
}

// Bad signature / unknown agent / replay each rejected + counted, stores nothing.
func TestUnverifiableRejected(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	publishRaw := func(env *corev1.SignedTelemetry) {
		b, _ := proto.Marshal(env)
		_ = conn.Publish(natsx.SubjectSigned, b)
	}

	// Unknown agent (never enrolled).
	unknown, _ := identity.Generate("nobody")
	payload, _ := proto.Marshal(&corev1.Event{EventId: "u1", AgentId: "nobody"})
	publishRaw(&corev1.SignedTelemetry{AgentId: "nobody", Sequence: 1, Kind: "event",
		Payload: payload, Signature: unknown.Sign(1, payload)})

	// Enrolled agent, but a corrupted signature.
	pub := signedAgent(t, srv, conn, "agent-badsig")
	_ = pub // enroll it
	badPayload, _ := proto.Marshal(&corev1.Event{EventId: "b1", AgentId: "agent-badsig"})
	publishRaw(&corev1.SignedTelemetry{AgentId: "agent-badsig", Sequence: 1, Kind: "event",
		Payload: badPayload, Signature: []byte("not a valid signature at all!!")})

	waitFor(t, func() bool { return srv.RejectedTelemetry.Load() >= 2 })
	if srv.RejectedTelemetry.Load() < 2 {
		t.Errorf("rejected = %d, want >= 2 (unknown agent + bad sig)", srv.RejectedTelemetry.Load())
	}
	// Nothing was stored for the rejected events.
	for _, ev := range []string{"u1", "b1"} {
		rows, _ := srv.TelemetryForEvent(context.Background(), ev)
		if len(rows) != 0 {
			t.Errorf("rejected event %q was stored", ev)
		}
	}
}

// A gap is recorded and the message still stored.
func TestSignedGapRecorded(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Enroll, then publish a message with a JUMPED sequence via a raw signer.
	ctx := context.Background()
	tok, _ := srv.IssueToken(ctx, time.Hour, time.Now())
	id, _ := identity.Generate("agent-gap")
	_ = srv.Enroll(ctx, tok, "agent-gap", id.PublicKey(), time.Now())

	payload, _ := proto.Marshal(&corev1.Event{EventId: "g1", AgentId: "agent-gap"})
	env := &corev1.SignedTelemetry{AgentId: "agent-gap", Sequence: 5, Kind: "event", // jump to 5 (expected 1)
		Payload: payload, Signature: id.Sign(5, payload)}
	b, _ := proto.Marshal(env)
	_ = conn.Publish(natsx.SubjectSigned, b)

	waitFor(t, func() bool {
		rows, _ := srv.TelemetryForEvent(ctx, "g1")
		return len(rows) == 1
	})
	if srv.Gaps.Load() < 1 {
		t.Errorf("gaps = %d, want >= 1 — a jumped sequence is suppression", srv.Gaps.Load())
	}
}

// Legacy unsigned telemetry is stored verified=false.
func TestLegacySelfAsserted(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	tr, err := natsx.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	_ = tr.PublishEvent(context.Background(), &corev1.Event{EventId: "legacy-1", AgentId: "agent-legacy"})

	waitFor(t, func() bool {
		rows, _ := srv.TelemetryForEvent(context.Background(), "legacy-1")
		return len(rows) == 1
	})
	pool := mustPoolCP(t)
	defer pool.Close()
	var verified bool
	_ = pool.QueryRow(context.Background(), `SELECT verified FROM fleet_telemetry WHERE event_id='legacy-1'`).Scan(&verified)
	if verified {
		t.Error("legacy unsigned telemetry was marked verified — it is self-asserted (D41)")
	}
}
