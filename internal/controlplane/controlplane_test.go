package controlplane_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/store/postgres"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
	"google.golang.org/protobuf/proto"
)

const dsn = "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable"

// requireDB connects or skips LOUDLY — the control plane's persistence is only
// meaningfully tested against a real database.
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		msg := fmt.Sprintf("POSTGRES UNAVAILABLE at %s: %v", dsn, err)
		if os.Getenv("OPENSHIELD_REQUIRE_POSTGRES") != "" {
			t.Fatalf("%s\nOPENSHIELD_REQUIRE_POSTGRES is set: the control plane's persistence "+
				"must not be silently unverified.", msg)
		}
		fmt.Fprintf(os.Stderr, "\n!! SKIPPING CONTROL-PLANE TESTS !! %s\n\n", msg)
		t.Skip(msg)
	}
	// lockDB BLOCKS on the cross-package advisory lock; under `-race` that wait can
	// exceed the 5s connect deadline above, so ALL post-lock DDL (drop AND migrate)
	// needs a FRESH deadline — otherwise the lock wait eats the original ctx and
	// the work fails "context deadline exceeded".
	lockDB(t, pool)
	ddlCtx, ddlCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer ddlCancel()
	if _, err := pool.Exec(ddlCtx, `DROP TABLE IF EXISTS investigation_views, agent_identities, enrollment_tokens, fleet_telemetry, peer_alerts, audit_entries, key_epochs, anchors, case_notes, cases, approvals, legal_holds, incidents, incident_alerts, incident_escalations, saved_searches, agent_enforcement, fleet_controls, config_changes, config_revisions, config_settings, itsm_tickets, runner_actions, ioc_indicators, ioc_feeds, playbook_steps, playbook_runs, incident_annotations, ueba_baselines, external_logs, notify_dedupe, unified_alerts, retention_events, entities, entity_aliases, schema_migrations CASCADE`); err != nil {
		t.Fatalf("clearing schema: %v", err)
	}
	if err := postgres.Migrate(ddlCtx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// embeddedNATS starts an in-process NATS server and returns its URL.
func embeddedNATS(t *testing.T) string {
	t.Helper()
	// JetStream enabled (with a per-test store dir) so PLAT-2 durable-ingest tests work; core-NATS
	// tests are unaffected (a JetStream-enabled server still serves core pub/sub identically).
	opts := &natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("embedded NATS did not become ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv.ClientURL()
}

// startCorrelationLoop runs the scheduled correlation loop for the duration of one test and — the part
// that matters — WAITS FOR IT TO HAVE STOPPED before the test's pool is closed.
//
// `go srv.RunCorrelationLoop(...)` with a `defer cancel()` looks like it stops the loop and only ASKS
// it to: cancel returns while the goroutine may still be inside a query, and Go runs a test's deferred
// calls before its t.Cleanup functions — so `t.Cleanup(pool.Close)` from requireDB could and did fire
// first. The next tick then failed against a closed pool and incremented `CorrelationFailures`, which
// is a PACKAGE-LEVEL counter, so the test that paid for the leak was a different one in a different
// file (TestScheduledCorrelationRaisesAndPagesWithNoOperatorRequest, ~2 runs in 6). A loop still running
// after its test finished is the defect; resetting the counter it writes to would only hide it.
//
// Registering the cleanup HERE — after requireDB has registered pool.Close — is what orders the two:
// cleanups run last-in-first-out, so the join happens strictly before the pool closes.
func startCorrelationLoop(t *testing.T, srv *controlplane.Server, interval func() time.Duration,
	rules func() (controlplane.CorrelationRule, controlplane.CrossDomainRule),
	hunts func() []controlplane.CrossDomainRule) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.RunCorrelationLoop(ctx, interval, rules, hunts,
			slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			// Bounded, and a FAILURE rather than a hang: a loop that will not stop is exactly the
			// thing this helper exists to catch, and blocking forever would report it as a timeout in
			// whichever test the harness happened to be in.
			t.Error("the correlation loop did not stop within 10s of its context being cancelled — it " +
				"is about to run against a closed pool and count failures against another test")
		}
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

// The full round trip: agent transport publishes over an embedded NATS, the
// control plane persists, and it reads back — "agent connects, telemetry lands
// in Postgres, CLI reads it back" (T-023 acceptance).
func TestTelemetryRoundTrip(t *testing.T) {
	pool := requireDB(t)
	url := embeddedNATS(t)

	srv := controlplane.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx, url) }()
	// Give the subscriptions a moment to establish.
	time.Sleep(100 * time.Millisecond)

	tr, err := natsx.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	if err := tr.PublishEvent(context.Background(), &corev1.Event{
		EventId: "e1", AgentId: "agent-A", Kind: corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
		Subject: &corev1.Subject{PseudonymousId: "sub_agent_a"}, // R34-12: ingest requires a subject
	}); err != nil {
		t.Fatal(err)
	}
	if err := tr.PublishClassification(context.Background(), &corev1.ClassificationSummary{
		EventId: "e1", DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF, Confidence: 0.9, MatchCount: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tr.PublishDecision(context.Background(), &corev1.Decision{
		DecisionId: "d1", EventId: "e1", Action: corev1.Action_ACTION_ALERT,
	}); err != nil {
		t.Fatal(err)
	}

	// Read back by event: all three kinds landed.
	waitFor(t, func() bool {
		rows, _ := srv.TelemetryForEvent(context.Background(), "e1")
		return len(rows) == 3
	})
	rows, err := srv.TelemetryForEvent(context.Background(), "e1")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, r := range rows {
		kinds[r.Kind] = true
	}
	for _, want := range []string{"event", "classification", "decision"} {
		if !kinds[want] {
			t.Errorf("kind %q did not land for event e1", want)
		}
	}

	// Read back by agent: the event is attributed to agent-A.
	byAgent, err := srv.Telemetry(context.Background(), "agent-A")
	if err != nil {
		t.Fatal(err)
	}
	if len(byAgent) != 1 || byAgent[0].Kind != "event" {
		t.Errorf("agent-A telemetry = %+v, want one event row", byAgent)
	}
}

// Only boundary-safe telemetry can arrive: a stored classification is a
// ClassificationSummary — type + confidence + count, no content.
func TestNoContentInAggregate(t *testing.T) {
	pool := requireDB(t)
	url := embeddedNATS(t)
	srv := controlplane.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx, url) }()
	time.Sleep(100 * time.Millisecond)

	tr, _ := natsx.Connect(url)
	defer tr.Close()
	_ = tr.PublishClassification(context.Background(), &corev1.ClassificationSummary{
		EventId: "e2", DetectorType: corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD, Confidence: 0.9, MatchCount: 1,
	})

	waitFor(t, func() bool {
		rows, _ := srv.TelemetryForEvent(context.Background(), "e2")
		return len(rows) == 1
	})
	rows, _ := srv.TelemetryForEvent(context.Background(), "e2")
	// The stored payload decodes as a ClassificationSummary, whose field set is
	// type + confidence + count by construction — the transport has no method
	// accepting LocalClassification, so content cannot have arrived. Decode and
	// assert exactly those fields round-tripped.
	var got corev1.ClassificationSummary
	if err := proto.Unmarshal(rows[0].Payload, &got); err != nil {
		t.Fatalf("stored classification does not decode as a summary: %v", err)
	}
	if got.GetDetectorType() != corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD ||
		got.GetMatchCount() != 1 || got.GetConfidence() == 0 {
		t.Errorf("summary round-trip wrong: %+v", &got)
	}
	// Structural guarantee, asserted: the summary message has exactly the four
	// boundary-safe fields and nothing that could carry content.
	fields := got.ProtoReflect().Descriptor().Fields()
	names := map[string]bool{}
	for i := 0; i < fields.Len(); i++ {
		names[string(fields.Get(i).Name())] = true
	}
	for _, f := range []string{"event_id", "detector_type", "confidence", "match_count"} {
		if !names[f] {
			t.Errorf("summary missing expected field %q", f)
		}
	}
	if len(names) != 4 {
		t.Errorf("ClassificationSummary has %d fields %v, want exactly 4 — a new field could "+
			"carry content across the boundary", len(names), names)
	}
}

// A malformed message is COUNTED (DecodeFailures), not silently dropped, and the
// subscription keeps working afterward.
func TestMalformedIsCountedNotSilent(t *testing.T) {
	pool := requireDB(t)
	url := embeddedNATS(t)
	srv := controlplane.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx, url) }()
	time.Sleep(100 * time.Millisecond)

	// Publish raw garbage to the events subject, bypassing the typed transport.
	nc, err := natsConnect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	if err := nc.Publish(natsx.SubjectEvents, []byte{0xff, 0xff, 0xff, 0xff, 0xff}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, func() bool { return srv.DecodeFailures.Load() >= 1 })
	if srv.DecodeFailures.Load() < 1 {
		t.Error("a malformed message was not counted — a silent vanish is the missing-evidence failure")
	}

	// The subscription still works: a valid event afterward lands.
	tr, _ := natsx.Connect(url)
	defer tr.Close()
	_ = tr.PublishEvent(context.Background(), &corev1.Event{EventId: "e-after", AgentId: "agent-B", Subject: &corev1.Subject{PseudonymousId: "sub_agent_b"}})
	waitFor(t, func() bool {
		rows, _ := srv.TelemetryForEvent(context.Background(), "e-after")
		return len(rows) == 1
	})
}

func natsConnect(url string) (*nats.Conn, error) { return nats.Connect(url) }

// lockDB holds a process-wide advisory lock for the whole test binary,
// serializing DB-mutating tests against the parallel postgres package that shares
// this database (see that package for the rationale). Same lock key; acquired
// once per process.
var (
	dbLockOnce sync.Once
	dbLockConn *pgx.Conn // package-level so the held lock connection is not GC-closed
)

func lockDB(t *testing.T, _ *pgxpool.Pool) {
	t.Helper()
	dbLockOnce.Do(func() {
		conn, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			t.Fatalf("lock connection: %v", err)
		}
		if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_lock(920431)`); err != nil {
			t.Fatalf("acquiring advisory lock: %v", err)
		}
		dbLockConn = conn // keep the connection (and thus the lock) alive for the process
	})
}
