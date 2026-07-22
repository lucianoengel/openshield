package gateway_test

import (
	"context"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
)

// TestGatewayThreatFeedHotSwap (NIPS-2 hot reload): swapping the feed at runtime changes the live
// verdict — a flow that was clean under the old feed is BLOCKED once a feed listing its destination is
// installed, with no gateway rebuild. This is what makes a background feed reload actually take effect.
//
// Mutation: if the pipeline captured the feed pointer at build time instead of reading the current one
// (g.threatFeed.Load() per request), the post-swap flow would still be ALLOWED → this FAILs.
func TestGatewayThreatFeedHotSwap(t *testing.T) {
	g := gateway.New(&fakeWorker{}, threatPolicy(t), &recLedger{}, nil, 10*time.Second)
	g.SetThreatFeed(feedTo(t, "domain old.evil.com\n"))

	flow := func(id, host string) *gateway.Request {
		return &gateway.Request{
			FlowID: id, SrcIP: "10.0.0.5", DstIP: "203.0.113.9", Protocol: "tcp",
			Host: host, Method: "GET", Path: "/",
			Direction: corev1.NetworkDirection_NETWORK_DIRECTION_EGRESS,
		}
	}

	// Under the initial feed, a flow to new.evil.com is clean → ALLOW.
	dec, err := g.Process(context.Background(), flow("f1", "new.evil.com"))
	if err != nil {
		t.Fatal(err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Fatalf("pre-swap flow = %v, want ALLOW", dec.GetAction())
	}

	// Hot-swap in a feed that lists new.evil.com — as a background reload would.
	g.SetThreatFeed(feedTo(t, "domain old.evil.com\ndomain new.evil.com\n"))

	// The SAME destination is now known-bad → BLOCK, with no gateway rebuild.
	dec, err = g.Process(context.Background(), flow("f2", "new.evil.com"))
	if err != nil {
		t.Fatal(err)
	}
	if dec.GetAction() != corev1.Action_ACTION_BLOCK {
		t.Fatalf("post-swap flow to a newly-listed domain = %v, want BLOCK — the feed swap was not observed", dec.GetAction())
	}
}
