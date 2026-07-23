package controlplane_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/notify"
)

// TestFullNotifyPathDeliversOnce (R34 test proposal #9 — SIEM-12 real coverage): the WHOLE notify path
// — verified telemetry ingest → observePeer → emit → deliverLoop → Webhook — delivers a peer alert to
// a real HTTP endpoint, and re-sent above-threshold telemetry for the same subject/window pages EXACTLY
// ONCE. No prior test drives this end-to-end (they stop at the peer_alerts row or call emit directly).
//
// Mutation: if the deliverLoop or the dedup were broken, the webhook would receive zero or two POSTs —
// the exactly-one assertion catches both.
func TestFullNotifyPathDeliversOnce(t *testing.T) {
	var posts atomic.Int64
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()

	url := embeddedNATS(t)
	srv := runServerPeer(t, url, 0.5, time.Hour) // long cooldown: the burst is one rising edge
	srv.SetNotifier(notify.NewWebhook(webhook.URL))

	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pub := signedAgent(t, srv, conn, "agent-notify")
	ctx := context.Background()

	// A population + an outlier, exactly as the peer-alert path expects.
	for _, s := range []string{"n1", "n2", "n3"} {
		for i := 0; i < 3; i++ {
			if err := pub.PublishEvent(ctx, eventFor("e", s)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := 0; i < 40; i++ {
		if err := pub.PublishEvent(ctx, eventFor("e", "outlier-n")); err != nil {
			t.Fatal(err)
		}
	}

	// The alert is delivered to the real webhook (end-to-end through deliverLoop).
	waitFor(t, func() bool { return posts.Load() >= 1 })

	// Re-send the outlier telemetry — a re-detection. It must NOT produce a second page.
	for i := 0; i < 40; i++ {
		if err := pub.PublishEvent(ctx, eventFor("e", "outlier-n")); err != nil {
			t.Fatal(err)
		}
	}
	// Give any erroneous second delivery time to arrive, then assert exactly one.
	time.Sleep(500 * time.Millisecond)
	if n := posts.Load(); n != 1 {
		t.Fatalf("webhook received %d POSTs, want exactly 1 — the full notify path did not dedupe a re-detection", n)
	}
}
