package controlplane_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/controlplane"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// PLAT-2: with durable JetStream ingest, telemetry published while the control-plane consumer is DOWN
// is NOT lost — it is retained in the stream and delivered + persisted once the consumer starts. This
// is the exact scenario at-most-once core NATS loses (a message with no live subscriber is dropped).
func TestJetStreamDurableIngestSurvivesDownConsumer(t *testing.T) {
	t.Setenv("OPENSHIELD_JETSTREAM", "1")
	pool := requireDB(t)
	url := embeddedNATS(t)

	srv := controlplane.New(pool)
	ctx := context.Background()
	// Enroll the agent (DB only — the consumer is NOT running yet).
	tok, err := srv.IssueToken(ctx, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Generate("agent-js")
	if err := srv.Enroll(ctx, tok, "agent-js", id.PublicKey(), time.Now()); err != nil {
		t.Fatal(err)
	}

	// Publish N SIGNED envelopes into the durable stream while nothing consumes them.
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pub, err := natsx.NewSignedPublisherWithSeq("agent-js", id, conn, natsx.NewFileSeqStore(filepath.Join(t.TempDir(), "seq")))
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.UseJetStream(); err != nil {
		t.Fatalf("UseJetStream: %v", err)
	}
	const N = 5
	for i := 0; i < N; i++ {
		if err := pub.PublishEvent(ctx, &corev1.Event{EventId: fmt.Sprintf("js-ev-%d", i), AgentId: "agent-js"}); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}
	// Sanity: nothing is persisted yet — the consumer is down.
	if rows, _ := srv.TelemetryForEvent(ctx, "js-ev-0"); len(rows) != 0 {
		t.Fatalf("telemetry persisted before the consumer ran (%d rows) — the test is not exercising a down consumer", len(rows))
	}

	// NOW start the durable consumer. It drains the backlog from the stream.
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.Run(rctx, url) }()

	// Every one of the N messages is delivered and persisted — none lost.
	for i := 0; i < N; i++ {
		ev := fmt.Sprintf("js-ev-%d", i)
		waitFor(t, func() bool {
			rows, _ := srv.TelemetryForEvent(ctx, ev)
			return len(rows) == 1
		})
	}
}

// PLAT-2: the per-agent advisory lock in VerifySigned serializes concurrent same-agent messages, so
// exactly ONE of many concurrent submissions of the SAME sequence is accepted and the rest are
// rejected as replays — without the lock, a race would let more than one through with one sequence.
func TestVerifySignedSerializesConcurrentSameAgent(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	tok, err := srv.IssueToken(ctx, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Generate("agent-race")
	if err := srv.Enroll(ctx, tok, "agent-race", id.PublicKey(), time.Now()); err != nil {
		t.Fatal(err)
	}

	// Fire many concurrent VerifySigned for the SAME sequence (1). Exactly one may win; the rest must
	// see the updated last_sequence and be rejected as replays.
	const workers = 20
	payload := []byte("p")
	sig := id.Sign(1, payload)
	var accepted int32
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := srv.VerifySigned(ctx, "agent-race", 1, payload, sig, time.Now())
			if err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if accepted != 1 {
		t.Errorf("concurrent same-sequence submissions accepted = %d, want exactly 1 (the advisory lock must serialize the sequence check)", accepted)
	}
}
