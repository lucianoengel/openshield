package controlplane_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// 3.3 — a restarted agent (a fresh publisher resuming from its persisted seq file)
// has its telemetry ACCEPTED, not rejected as a replay (D66). Before the fix, the
// in-memory counter reset to 0 and the post-restart messages were ErrReplay.
func TestRestartedAgentNotReplayed(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx := context.Background()
	tok, _ := srv.IssueToken(ctx, time.Hour, time.Now())
	id, _ := identity.Generate("agent-restart")
	if err := srv.Enroll(ctx, tok, "agent-restart", id.PublicKey(), time.Now()); err != nil {
		t.Fatal(err)
	}
	seqFile := filepath.Join(t.TempDir(), "seq")

	// Pre-restart: publish and confirm it lands.
	pub1, err := natsx.NewSignedPublisherWithSeq("agent-restart", id, conn, natsx.NewFileSeqStore(seqFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := pub1.PublishEvent(ctx, &corev1.Event{EventId: "ev-pre", AgentId: "agent-restart", Subject: &corev1.Subject{PseudonymousId: "sub_restart"}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		rows, _ := srv.TelemetryForEvent(ctx, "ev-pre")
		return len(rows) == 1
	})
	rejectedBefore := srv.RejectedTelemetry.Load()

	// RESTART: a new publisher from the SAME seq file, same identity.
	pub2, err := natsx.NewSignedPublisherWithSeq("agent-restart", id, conn, natsx.NewFileSeqStore(seqFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := pub2.PublishEvent(ctx, &corev1.Event{EventId: "ev-post", AgentId: "agent-restart", Subject: &corev1.Subject{PseudonymousId: "sub_restart"}}); err != nil {
		t.Fatal(err)
	}

	// The post-restart message is accepted (stored), NOT rejected as a replay.
	waitFor(t, func() bool {
		rows, _ := srv.TelemetryForEvent(ctx, "ev-post")
		return len(rows) == 1
	})
	if got := srv.RejectedTelemetry.Load(); got != rejectedBefore {
		t.Errorf("post-restart telemetry was rejected (%d→%d) — the false-replay bug is present", rejectedBefore, got)
	}
}
