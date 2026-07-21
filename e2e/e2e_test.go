//go:build e2e

// Package e2e drives the RUNNING containerised stack from outside (T-023 e2e).
//
// Unlike the in-process control-plane tests (real Postgres, EMBEDDED NATS), this
// exercises the actual openshield-server BINARY in a container, talking to a real
// NATS container and a real Postgres container. It publishes telemetry over the
// exposed NATS and verifies it lands in the exposed Postgres — the wire path
// where container/config bugs hide.
//
// Tagged `e2e` so it never runs in the normal suite. Driven by deploy/e2e.sh,
// which brings the stack up and sets the env below.
package e2e_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// TestContainerRoundTrip publishes telemetry over the real NATS container and
// verifies the containerised server persisted it to the real Postgres container.
func TestContainerRoundTrip(t *testing.T) {
	natsURL := env("OPENSHIELD_E2E_NATS", "nats://127.0.0.1:4222")
	dsn := env("OPENSHIELD_E2E_DSN", "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable")
	eventID := env("OPENSHIELD_E2E_EVENT", "e2e-default")

	// Publish via the SAME transport the agent uses, to the real NATS container.
	tr, err := natsx.Connect(natsURL)
	if err != nil {
		t.Fatalf("connect NATS %s: %v", natsURL, err)
	}
	defer tr.Close()

	ctx := context.Background()
	if err := tr.PublishEvent(ctx, &corev1.Event{
		EventId: eventID, AgentId: "e2e-agent", Kind: corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
	}); err != nil {
		t.Fatalf("publish event: %v", err)
	}
	if err := tr.PublishClassification(ctx, &corev1.ClassificationSummary{
		EventId: eventID, DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF, Confidence: 0.9, MatchCount: 1,
	}); err != nil {
		t.Fatalf("publish classification: %v", err)
	}
	if err := tr.PublishDecision(ctx, &corev1.Decision{
		DecisionId: "e2e-d", EventId: eventID, Action: corev1.Action_ACTION_ALERT,
	}); err != nil {
		t.Fatalf("publish decision: %v", err)
	}

	// Verify against the real Postgres container. Poll, don't sleep — the server
	// persists asynchronously; a bounded poll passes as soon as the rows land and
	// fails loudly if they never do.
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect Postgres %s: %v", dsn, err)
	}
	defer pool.Close()

	deadline := time.Now().Add(15 * time.Second)
	var kinds []string
	for time.Now().Before(deadline) {
		kinds = kinds[:0]
		rows, err := pool.Query(ctx,
			`SELECT kind FROM fleet_telemetry WHERE event_id = $1 ORDER BY id`, eventID)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		for rows.Next() {
			var k string
			_ = rows.Scan(&k)
			kinds = append(kinds, k)
		}
		rows.Close()
		if len(kinds) == 3 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if len(kinds) != 3 {
		t.Fatalf("event %q: got %d telemetry rows %v in the containerised store, want 3 "+
			"(event, classification, decision) — the server binary did not persist real telemetry "+
			"off real NATS", eventID, len(kinds), kinds)
	}
	seen := map[string]bool{}
	for _, k := range kinds {
		seen[k] = true
	}
	for _, want := range []string{"event", "classification", "decision"} {
		if !seen[want] {
			t.Errorf("kind %q did not land end to end", want)
		}
	}
	t.Logf("e2e OK: 3 telemetry rows for %q persisted by the containerised server", eventID)
}
