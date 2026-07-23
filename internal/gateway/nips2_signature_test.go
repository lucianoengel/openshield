package gateway_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/policy"
)

// buildWorkerBin builds the real openshield-worker once per test.
func buildWorkerBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "openshield-worker")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/openshield-worker").CombinedOutput(); err != nil {
		t.Fatalf("building worker: %v\n%s", err, out)
	}
	return bin
}

// startWorkerWithRules starts the REAL worker subprocess with a NIPS ruleset file, so
// content-signature matching runs where it must — behind the sandbox (D72).
func startWorkerWithRules(t *testing.T, bin, rulesPath string) *privileged.Worker {
	t.Helper()
	t.Setenv("OPENSHIELD_NIPS_RULES", rulesPath)
	w, err := privileged.StartWorker(context.Background(), bin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}

func writeRules(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nips-rules.txt")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// threatCountPolicy blocks a flow only when it carries at least `min` threat matches.
// With min=1 it blocks on any threat; with min=2 it proves BOTH a metadata and a
// content match reached the policy (the merge guard).
func threatCountPolicy(t *testing.T, min int) core.Stage {
	t.Helper()
	src := `package openshield
import rego.v1
default n := 0
n := count(input.threat.matches) if { input.threat }
decision := {"action":"BLOCK","reason":"threat","confidence":0.9} if { n >= ` + itoa(min) + ` }
decision := {"action":"ALLOW","reason":"clean","confidence":0.9} if { n < ` + itoa(min) + ` }`
	pol, err := policy.New(context.Background(), "nips2", "1", src)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func itoa(n int) string { return string(rune('0' + n)) }

// TestContentSignatureBlocksMaliciousBody drives the REAL gateway→worker path: a body
// carrying a rule's pattern is matched by the content-signature engine IN THE WORKER,
// projected onto the threat axis, and a prevent-policy BLOCKs it — the network plane
// acting as an IPS on content, not just metadata. No seeded literals: the worker binary
// loads the ruleset from OPENSHIELD_NIPS_RULES and matches the actual body bytes.
//
// Mutation (signature.Match returns nil): no threat match is produced → the flow is
// ALLOWED → this test FAILs.
func TestContentSignatureBlocksMaliciousBody(t *testing.T) {
	bin := buildWorkerBin(t)
	rules := writeRules(t, "rule evil-payload\ncontent __MALICIOUS_MARKER__\nend\n")
	w := startWorkerWithRules(t, bin, rules)

	g := gateway.NewFromWorker(w, threatCountPolicy(t, 1), &recLedger{}, nil, 10*time.Second)

	dec, err := g.Process(context.Background(), req("flow-sig", "prefix __MALICIOUS_MARKER__ suffix"))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_BLOCK {
		t.Fatalf("a body tripping a content signature = %v, want BLOCK", dec.GetAction())
	}
}

// TestContentSignatureCleanBodyAllowed: a body matching no rule carries no
// content-signature match and is allowed (the engine never denies on its own).
func TestContentSignatureCleanBodyAllowed(t *testing.T) {
	bin := buildWorkerBin(t)
	rules := writeRules(t, "rule evil-payload\ncontent __MALICIOUS_MARKER__\nend\n")
	w := startWorkerWithRules(t, bin, rules)

	g := gateway.NewFromWorker(w, threatCountPolicy(t, 1), &recLedger{}, nil, 10*time.Second)

	dec, err := g.Process(context.Background(), req("flow-clean", "a perfectly ordinary body"))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Fatalf("clean body = %v, want ALLOW", dec.GetAction())
	}
}

// TestBothMetadataAndContentMatchReachPolicy is the MERGE guard: one flow trips BOTH an
// IOC metadata match (bad host, via the feed) AND a content signature (body). The policy
// blocks only when it sees >= 2 threat matches, so it passes only if BOTH survived —
// proving the content-signature projection and the IOC stage APPEND to one classification
// rather than overwriting.
//
// Mutation (net-threat stage overwrites st.Threats = tc instead of appending): only 1
// match survives → n < 2 → ALLOW → this test FAILs.
func TestBothMetadataAndContentMatchReachPolicy(t *testing.T) {
	bin := buildWorkerBin(t)
	rules := writeRules(t, "rule evil-payload\ncontent __MALICIOUS_MARKER__\nend\n")
	w := startWorkerWithRules(t, bin, rules)

	g := gateway.NewFromWorker(w, threatCountPolicy(t, 2), &recLedger{}, nil, 10*time.Second)
	g.SetThreatFeed(feedTo(t, "domain c2.evil.com\n"))

	r := &gateway.Request{
		FlowID: "flow-both", SrcIP: "10.0.0.5", DstIP: "203.0.113.9", Protocol: "tcp",
		Host: "beacon.c2.evil.com", Method: "POST", Path: "/upload",
		Body:      []byte("payload __MALICIOUS_MARKER__ here"),
		Direction: corev1.NetworkDirection_NETWORK_DIRECTION_EGRESS,
	}
	dec, err := g.Process(context.Background(), r)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_BLOCK {
		t.Fatalf("a flow with BOTH an IOC and a content-signature match = %v, want BLOCK "+
			"(the policy needs both — a merge that overwrites drops one)", dec.GetAction())
	}
}

// TestContentSignatureHotReload proves a signature added to the ruleset file at runtime
// takes effect with no worker restart: a body previously allowed becomes blocked after the
// worker's watcher reloads.
//
// Mutation (watcher reads its baseline async / never reloads): the second Process stays
// ALLOW → this test FAILs.
func TestContentSignatureHotReload(t *testing.T) {
	bin := buildWorkerBin(t)
	rules := writeRules(t, "rule initial\ncontent HARMLESS\nend\n")
	w := startWorkerWithRules(t, bin, rules)

	g := gateway.NewFromWorker(w, threatCountPolicy(t, 1), &recLedger{}, nil, 10*time.Second)

	// Before the reload, the marker body is clean → allowed.
	dec, err := g.Process(context.Background(), req("flow-pre", "body with __LATE_MARKER__"))
	if err != nil {
		t.Fatal(err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Fatalf("pre-reload = %v, want ALLOW", dec.GetAction())
	}

	// Add a rule for the marker and bump mtime forward so the worker's watcher reloads.
	if err := os.WriteFile(rules, []byte("rule initial\ncontent HARMLESS\nend\nrule late\ncontent __LATE_MARKER__\nend\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(rules, future, future); err != nil {
		t.Fatal(err)
	}

	// The worker polls every 2s; retry until the reloaded rule blocks the same body.
	deadline := time.Now().Add(8 * time.Second)
	for {
		dec, err := g.Process(context.Background(), req("flow-post", "body with __LATE_MARKER__"))
		if err != nil {
			t.Fatal(err)
		}
		if dec.GetAction() == corev1.Action_ACTION_BLOCK {
			return // the added signature took effect without a restart
		}
		if time.Now().After(deadline) {
			t.Fatal("the added signature never took effect — hot-reload did not reach the worker")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
