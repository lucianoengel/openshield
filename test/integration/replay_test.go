//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// DECISION REPLAY END TO END (`openshieldctl replay`).
//
// The platform's thesis is that every decision is explainable, REPRODUCIBLE, and cryptographically
// auditable. `openshieldctl verify` has always covered the auditable half. `core.Replay` and
// `core.DecisionsEquivalent` implemented the reproducible half carefully — an explicit allowlist of
// compared fields, so that adding a field forces a deliberate decision about whether replay should
// compare it — and had NO CALLER. Nobody had ever replayed a decision.
//
// The scenario replays a decision the ENGINE wrote, not one constructed in Go: the recorded decision
// has to have come through the real pipeline for "it reproduces" to mean anything.

// networkEventJSON is an event whose decision turns on METADATA alone.
//
// That is deliberate and it is the honest shape of this command. openshieldctl is READ-ONLY and holds
// no sandboxed worker, so it replays the POLICY, not the classifier. A decision that turned on file
// CONTENT could not be reproduced by a CLI that cannot open the file — and the ledger stores no content
// to reproduce it from, which is the privacy property (D10/D29) rather than a gap.
const networkEventJSON = `{
  "connectorId": "dns",
  "eventId": "%s",
  "kind": "EVENT_KIND_DNS_QUERY",
  "purpose": "PURPOSE_DLP",
  "network": {"flowId": "1", "srcIp": "10.0.0.9", "dstPort": 53, "protocol": "udp", "sniHost": "%s"}
}`

// TestARecordedDecisionReplaysAndAPolicyChangeDiverges.
//
// BOTH HALVES. "The changed policy diverged" is satisfied by a command that reports divergence for
// everything — which would be a gate that always fails and therefore always gets disabled.
func TestARecordedDecisionReplaysAndAPolicyChangeDiverges(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	addr := "127.0.0.1:" + freePort(t)

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_DNS_LISTEN=" + addr,
	})
	eng.WaitForOutput("DNS connector ENABLED", 90*time.Second)

	// A TUNNELLING name, so the engine records an ALERT rather than an ALLOW. Replaying an ALLOW would
	// pass against a policy that allows everything, including one that no longer evaluates at all.
	pool := openPool(t, stack.DSN)
	alerts := func() int {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries WHERE action = 2`).Scan(&n)
		return n
	}
	Eventually(t, 90*time.Second, "the engine to record an ALERT worth replaying", func() bool {
		dnsTap(t, addr, tunnelledName)
		return alerts() > 0
	})

	// The event id the engine minted for it — replay looks the decision up by that id, so it has to be
	// the real one rather than a guess about the connector's numbering.
	var eventID string
	if err := pool.QueryRow(Ctx(t),
		`SELECT event_id FROM audit_entries WHERE action = 2 ORDER BY sequence DESC LIMIT 1`).
		Scan(&eventID); err != nil {
		t.Fatal(err)
	}

	evPath := filepath.Join(work, "event.json")
	writeEvent := func(host string) {
		t.Helper()
		body := []byte(fmt.Sprintf(networkEventJSON, eventID, host))
		if err := os.WriteFile(evPath, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// 1. THE SAME INPUT REPRODUCES the recorded decision.
	writeEvent(tunnelledName)
	out, err := runCapture(t, "openshieldctl", nil, "replay", "--dsn", stack.DSN, "--event", evPath)
	if err != nil {
		t.Fatalf("replaying a decision the engine itself recorded did NOT reproduce it: %v\n%s", err, out)
	}
	if !contains(out, "REPRODUCED") {
		t.Fatalf("the replay did not report REPRODUCED:\n%s", out)
	}
	// The success report must not overstate what it established — the ledger holds no content, and the
	// event came from the operator.
	if !contains(out, "does not establish") {
		t.Errorf("a successful replay does not state that the input is unverified:\n%s", out)
	}

	// 2. A DIFFERENT INPUT DIVERGES. Same event id, an ordinary name — so the policy that alerted on a
	// tunnelling score now allows, which is exactly the "the INPUT changed" case the report warns about.
	writeEvent("www.example.com")
	out, err = runCapture(t, "openshieldctl", nil, "replay", "--dsn", stack.DSN, "--event", evPath)
	if err == nil {
		t.Fatalf("replaying a DIFFERENT input reproduced the recorded decision. The comparison is not "+
			"looking at the decision at all:\n%s", out)
	}
	if !contains(out, "DIVERGED") {
		t.Errorf("the report does not say DIVERGED:\n%s", out)
	}
	for _, want := range []string{"POLICY changed", "INPUT changed"} {
		if !contains(out, want) {
			t.Errorf("the divergence report does not name %q as a cause. An operator who reverts a "+
				"policy over an input that changed has been misled by an accurate report:\n%s", want, out)
		}
	}

	// 3. AN UNRECORDED EVENT is reported distinctly, not as a divergence — otherwise a typo in an event
	// id fails a policy gate as though the policy had regressed.
	if err := os.WriteFile(evPath,
		[]byte(fmt.Sprintf(networkEventJSON, "no-such-event-id", tunnelledName)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = runCapture(t, "openshieldctl", nil, "replay", "--dsn", stack.DSN, "--event", evPath)
	if err == nil {
		t.Fatalf("an event with no recorded decision replayed successfully:\n%s", out)
	}
	if contains(out, "DIVERGED") || !contains(out, "not a divergence") {
		t.Errorf("an unrecorded event was not distinguished from a divergence:\n%s", out)
	}
}
