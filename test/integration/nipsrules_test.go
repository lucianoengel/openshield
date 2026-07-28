//go:build integration

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// CONTENT SIGNATURES OVER A FLOW BODY (NIPS-2, OPENSHIELD_NIPS_RULES).
//
// The IOC feed decides on a flow's DESTINATION; this decides on its CONTENT — an exfiltration to a host
// nobody has heard of, a payload with a known marker. It is the half of NIPS that has to look at bytes,
// which is why it runs in the SANDBOXED WORKER (D72) and not in the gateway: the body is attacker
// content, and the process that parses attacker content is the one that must not hold the network or the
// keys.
//
// `internal/signature` measured at ZERO integration coverage. The unit tests cover the matcher; nothing
// ran it through a worker, which is where the interesting properties live — that the ruleset reaches the
// sandbox at all, that a malformed one stops the worker rather than leaving it matching nothing, and that
// what comes back is content-free.

const nipsRuleset = `# operator content signatures
rule exfil-marker
  confidence 0.95
  content SECRET-PROJECT-NIGHTJAR
end
rule case-insensitive-marker
  nocase
  content beacon-payload-v2
end
`

// blockOnThreatBody blocks when the worker reported any threat match.
const blockOnThreatBody = `package openshield
import rego.v1
decision := {"action":"BLOCK","reason":"content signature"} if { count(input.threat.matches) > 0 }
decision := {"action":"ALLOW","reason":"clean"} if { count(input.threat.matches) == 0 }`

// TestAContentSignatureBlocksAFlowAndLeaksNothing.
func TestAContentSignatureBlocksAFlowAndLeaksNothing(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	origin := startUpstream(t)

	rules := filepath.Join(work, "nips.rules")
	if err := os.WriteFile(rules, []byte(nipsRuleset), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(work, "block.rego")
	if err := os.WriteFile(policy, []byte(blockOnThreatBody), 0o600); err != nil {
		t.Fatal(err)
	}

	gw, addr := startGateway(t, stack,
		"OPENSHIELD_NIPS_RULES="+rules,
		"OPENSHIELD_POLICY_CUSTOM="+policy,
		"OPENSHIELD_ENFORCE=1")

	// A CLEAN body first. Without it "the marked body was blocked" is satisfied by a gateway that blocks
	// everything, which is an outage rather than a signature engine.
	clean, err := proxyClient(t, addr).Post("http://"+origin.addr+"/ok", "text/plain",
		strings.NewReader("an ordinary upload with nothing of interest\n"))
	if err != nil {
		t.Fatalf("proxying a clean body: %v\n%s", err, gw.Output())
	}
	clean.Body.Close()
	if clean.StatusCode != http.StatusOK {
		t.Fatalf("a CLEAN body was blocked (%d) — a signature engine that matches everything is an "+
			"outage\n%s", clean.StatusCode, gw.Output())
	}

	// The MARKED body is refused before it leaves.
	before := origin.hits.Load()
	marked, err := proxyClient(t, addr).Post("http://"+origin.addr+"/upload", "text/plain",
		strings.NewReader("payload: SECRET-PROJECT-NIGHTJAR trailing bytes\n"))
	if err != nil {
		t.Fatalf("proxying the marked body: %v\n%s", err, gw.Output())
	}
	defer marked.Body.Close()
	if marked.StatusCode != http.StatusForbidden {
		t.Errorf("a body carrying an operator signature returned %d, want 403 — the ruleset reached the "+
			"worker and matched nothing\n%s", marked.StatusCode, gw.Output())
	}
	if n := origin.hits.Load(); n != before {
		t.Errorf("the marked body REACHED the upstream (%d -> %d). A 403 to the client is not prevention "+
			"if the bytes left anyway", before, n)
	}

	// CASE-INSENSITIVE matching, since a marker in the wild rarely arrives in the case the rule was
	// written in — and a rule that only matches its own casing is a rule that matches in testing.
	upper, err := proxyClient(t, addr).Post("http://"+origin.addr+"/upload", "text/plain",
		strings.NewReader("BEACON-PAYLOAD-V2 in shouting case\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer upper.Body.Close()
	if upper.StatusCode != http.StatusForbidden {
		t.Errorf("a `nocase` rule did not match a differently-cased marker (%d)\n%s",
			upper.StatusCode, gw.Output())
	}

	// AND THE MATCH IS CONTENT-FREE. The worker sees the bytes; nothing downstream may. A ledger holding
	// the matched text would make the audit trail the leak it exists to detect (D10/D29).
	assertLedgerCarriesNone(t, stack, "SECRET-PROJECT-NIGHTJAR", "BEACON-PAYLOAD-V2")
}

// TestAMalformedNipsRulesetStopsTheWorker.
//
// The alternative is the failure this audit keeps finding: a worker that starts, fails to load its
// ruleset, and classifies every flow as clean. Nothing errors, the gateway reports itself healthy, and
// "no threats found" means "no threats were looked for" — which reads identically on a console.
func TestAMalformedNipsRulesetStopsTheWorker(t *testing.T) {
	work := t.TempDir()
	rules := filepath.Join(work, "broken.rules")
	if err := os.WriteFile(rules, []byte("rule unclosed\n  content something\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := refuseToStart(t, "openshield-worker", []string{"OPENSHIELD_NIPS_RULES=" + rules})
	if !contains(out, "NIPS ruleset") {
		t.Errorf("the refusal does not name the ruleset, so an operator cannot tell it from any other "+
			"startup failure:\n%s", out)
	}
}

// TestTheNipsRulesetHotReloads: a new signature takes effect without a restart, and a bad edit is
// served-stale — the same contract the IOC feed and the CASB catalog hold, and ordered the same way so
// the last step cannot pass vacuously.
func TestTheNipsRulesetHotReloads(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	origin := startUpstream(t)

	rules := filepath.Join(work, "nips.rules")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(rules, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// 1. A ruleset that does NOT name the marker, so the body starts out clean.
	write("rule unrelated\n  content SOMETHING-ELSE-ENTIRELY\nend\n")

	policy := filepath.Join(work, "block.rego")
	if err := os.WriteFile(policy, []byte(blockOnThreatBody), 0o600); err != nil {
		t.Fatal(err)
	}
	gw, addr := startGateway(t, stack,
		"OPENSHIELD_NIPS_RULES="+rules,
		"OPENSHIELD_POLICY_CUSTOM="+policy,
		"OPENSHIELD_ENFORCE=1")

	post := func() int {
		t.Helper()
		resp, err := proxyClient(t, addr).Post("http://"+origin.addr+"/upload", "text/plain",
			strings.NewReader("payload: SECRET-PROJECT-NIGHTJAR\n"))
		if err != nil {
			t.Fatalf("proxying: %v\n%s", err, gw.Output())
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(); code != http.StatusOK {
		t.Fatalf("step 1: a body matching NO rule returned %d, want 200\n%s", code, gw.Output())
	}

	// 2. The operator adds the signature. No restart.
	write(nipsRuleset)
	Eventually(t, 60*time.Second, "the added signature to take effect without a restart", func() bool {
		return post() == http.StatusForbidden
	})

	// 3. A typo. The running ruleset must survive it — a bad edit that disarmed the engine would turn
	// one mistake into a silent, fleet-wide loss of content inspection.
	write("rule broken\n  content ...\n")
	time.Sleep(5 * time.Second)
	if code := post(); code != http.StatusForbidden {
		t.Errorf("step 3: after a MALFORMED edit the flow returned %d, want 403 — the previously loaded "+
			"ruleset must be kept\n%s", code, gw.Output())
	}
}
