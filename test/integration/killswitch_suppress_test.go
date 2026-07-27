//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// INV-5, PROVEN PROPERLY: the kill switch SUPPRESSES AN ENFORCEMENT while detection continues (D299).
//
// The existing kill-switch scenarios assert that the switch CHANGES STATE — the process says
// "ENFORCEMENT DISABLED", and it is still running. That is not the invariant. INVARIANTS.md claims
// "enforcement can be stopped without stopping detection", and a state change proves neither half:
// a build that flipped the flag and enforced anyway would pass, and so would one that stopped
// classifying entirely.
//
// This is the same mistake D294 caught in the intent scenario — asserting on an announcement rather than
// on the behaviour it announces — and I published INVARIANTS.md citing those tests before noticing that
// its INV-5 row was doing it too. The claim was stronger than its demonstration.
//
// So: a file is QUARANTINED (moved) with the switch off, NOT moved with it engaged, and moved again once
// it is released — and in every case the detection still reaches the ledger.

// quarantineOnCPF is a policy that actually enforces, because the shipped default deliberately does not:
// it emits ALERT or ALLOW and never selects an enforcing verb (D1, observe-only by default). With the
// default policy the switch would have nothing to suppress, and the test would prove nothing while
// looking green.
const quarantineOnCPF = `package openshield
import rego.v1
hit if { some h in input.classification; h.type == "DETECTOR_TYPE_CPF" }
decision := {"action":"QUARANTINE_LOCAL","reason":"cpf"} if { hit }
decision := {"action":"ALLOW","reason":"clean"} if { not hit }`

func TestTheKillSwitchSuppressesEnforcementAndKeepsDetecting(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	watch := t.TempDir()
	qdir := filepath.Join(work, "quarantine")
	glass := filepath.Join(work, "EMERGENCY_DISABLE")
	policy := filepath.Join(work, "quarantine.rego")
	if err := os.WriteFile(policy, []byte(quarantineOnCPF), 0o600); err != nil {
		t.Fatal(err)
	}

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
		"OPENSHIELD_ENFORCE=1",
		"OPENSHIELD_QUARANTINE_DIR=" + qdir,
		"OPENSHIELD_BREAK_GLASS=" + glass,
		"OPENSHIELD_BREAK_GLASS_POLL=200ms",
	})
	eng.WaitForOutput("engine observing", 90*time.Second)
	pool := openPool(t, stack.DSN)

	const cpf = "name,cpf\nalice,111.444.777-35\n"
	drop := func(name string) string {
		t.Helper()
		p := filepath.Join(watch, name)
		if err := os.WriteFile(p, []byte(cpf), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	gone := func(p string) bool { _, err := os.Stat(p); return os.IsNotExist(err) }
	ledgerRows := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// 1. ENFORCING: the file is MOVED out of the watched directory into quarantine.
	before := drop("before.csv")
	Eventually(t, 120*time.Second, "the file to be quarantined while enforcement is ON", func() bool {
		return gone(before)
	})
	rowsAfterFirst := ledgerRows()
	if rowsAfterFirst == 0 {
		t.Fatalf("nothing was audited for the enforced file\n%s", eng.Output())
	}

	// 2. ENGAGE the switch.
	if err := os.WriteFile(glass, []byte("incident 41\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng.WaitForOutput("ENFORCEMENT DISABLED", 60*time.Second)

	// 3. SUPPRESSED: the next file is NOT moved — and IS still detected and recorded.
	during := drop("during.csv")
	Eventually(t, 120*time.Second, "the suppressed file to be audited", func() bool {
		return ledgerRows() > rowsAfterFirst
	})
	// Give any (incorrect) enforcement time to happen before concluding it did not.
	time.Sleep(3 * time.Second)
	if gone(during) {
		t.Errorf("the file was QUARANTINED WHILE THE KILL SWITCH WAS ENGAGED. The switch sits between "+
			"the decision and the enforcer; an operator who engages it and still has files moved out from "+
			"under users has no way to stop the product short of killing it\n%s", eng.Output())
	}
	// KEEP SEEING is the other half, and the one a naive implementation breaks: a switch that dropped the
	// event or skipped classification would also stop the file moving, while destroying the record of
	// what happened during the very window an operator will need to reconstruct.
	rowsAfterSuppressed := ledgerRows()
	if rowsAfterSuppressed <= rowsAfterFirst {
		t.Errorf("no audit entry was recorded while enforcement was suppressed — STOP ACTING, KEEP "+
			"SEEING: a switch implemented earlier in the pipeline destroys exactly the evidence the "+
			"incident needs\n%s", eng.Output())
	}

	// 4. RELEASE: enforcement resumes. A switch that cannot be un-flipped is a broken product, not a
	// safety control.
	if err := os.Remove(glass); err != nil {
		t.Fatal(err)
	}
	eng.WaitForOutput("enforcement RESTORED", 60*time.Second)
	after := drop("after.csv")
	Eventually(t, 120*time.Second, "enforcement to resume after the switch is released", func() bool {
		return gone(after)
	})
}
