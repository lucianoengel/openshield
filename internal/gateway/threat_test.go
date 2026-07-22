package gateway_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/nips"
	"github.com/lucianoengel/openshield/internal/policy"
)

// threatPolicy blocks a flow with any threat match, else allows. The body is clean
// (the fake worker returns no hits), so only the NIPS-2 threat signal decides.
func threatPolicy(t *testing.T) core.Stage {
	t.Helper()
	pol, err := policy.New(context.Background(), "nips", "1", `package openshield
import rego.v1
has_threat if { input.threat; count(input.threat.matches) > 0 }
decision := {"action":"BLOCK","reason":"known-bad destination","confidence":0.9} if { has_threat }
decision := {"action":"ALLOW","reason":"clean flow","confidence":0.9} if { not has_threat }`)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func feedTo(t *testing.T, body string) *nips.Feed {
	t.Helper()
	f, err := nips.ParseFeed(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestGatewayBlocksKnownBadDestination proves the NIPS-2 engine flags a flow to a
// feed-listed domain and the policy blocks it — the gateway acting as an IPS.
func TestGatewayBlocksKnownBadDestination(t *testing.T) {
	g := gateway.New(&fakeWorker{}, threatPolicy(t), &recLedger{}, nil, 10*time.Second)
	g.SetThreatFeed(feedTo(t, "domain c2.evil.com\n"))

	// A flow to a subdomain of the bad domain.
	r := &gateway.Request{
		FlowID: "f1", SrcIP: "10.0.0.5", DstIP: "203.0.113.9", Protocol: "tcp",
		Host: "beacon.c2.evil.com", Method: "GET", Path: "/",
		Direction: corev1.NetworkDirection_NETWORK_DIRECTION_EGRESS,
	}
	dec, err := g.Process(context.Background(), r)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_BLOCK {
		t.Fatalf("flow to known-bad domain = %v, want BLOCK", dec.GetAction())
	}
}

// TestGatewayAllowsCleanFlow proves a flow matching nothing on the feed carries no
// threat and is not blocked by the threat rule.
func TestGatewayAllowsCleanFlow(t *testing.T) {
	g := gateway.New(&fakeWorker{}, threatPolicy(t), &recLedger{}, nil, 10*time.Second)
	g.SetThreatFeed(feedTo(t, "domain c2.evil.com\n"))

	r := &gateway.Request{
		FlowID: "f2", SrcIP: "10.0.0.5", DstIP: "93.184.216.34", Protocol: "tcp",
		Host: "www.example.com", Method: "GET", Path: "/",
		Direction: corev1.NetworkDirection_NETWORK_DIRECTION_EGRESS,
	}
	dec, err := g.Process(context.Background(), r)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Fatalf("clean flow = %v, want ALLOW", dec.GetAction())
	}
}

// TestGatewayNoFeedNoThreatStage proves that without a feed the threat engine is
// inert — the same clean flow is allowed and no threat stage runs.
func TestGatewayNoFeedNoThreatStage(t *testing.T) {
	g := gateway.New(&fakeWorker{}, threatPolicy(t), &recLedger{}, nil, 10*time.Second)
	// No SetThreatFeed.
	r := &gateway.Request{
		FlowID: "f3", SrcIP: "10.0.0.5", DstIP: "203.0.113.9", Protocol: "tcp",
		Host: "beacon.c2.evil.com", Method: "GET", Path: "/",
		Direction: corev1.NetworkDirection_NETWORK_DIRECTION_EGRESS,
	}
	dec, err := g.Process(context.Background(), r)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	// With no feed, even a "bad" host carries no threat → allowed (fail open).
	if dec.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Fatalf("no-feed flow = %v, want ALLOW (engine inert)", dec.GetAction())
	}
}
