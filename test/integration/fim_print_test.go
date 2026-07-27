//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE LAST TWO BINARIES (D300): the FIM baseline tool and the CUPS print filter.
//
// Both are operator-facing halves of a capability whose other half is already covered, and both were
// the shape this session has repeatedly found dangerous: a tool that produces an artifact, and a
// consumer that verifies it, with nothing proving the two agree. `openshield-dlp-index` and the worker
// turned out to agree; `SignRuleBundle` had no producer at all until D297; `encryptlocal` could encrypt
// and nothing could decrypt until D293. The pattern is common enough that "the signer and the verifier
// are in the same repository" is not evidence.

// TestTheFIMBaselineToolProducesWhatTheEngineVerifies closes the loop for HIPS-4.
func TestTheFIMBaselineToolProducesWhatTheEngineVerifies(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	critical := filepath.Join(work, "critical")
	if err := os.MkdirAll(critical, 0o755); err != nil {
		t.Fatal(err)
	}
	guarded := filepath.Join(critical, "sudoers")
	if err := os.WriteFile(guarded, []byte("root ALL=(ALL) ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	key, pub := filepath.Join(work, "fim.key"), filepath.Join(work, "fim.pub")
	if out, err := runCapture(t, "openshield-fim-baseline", nil,
		"keygen", "--out-key", key, "--out-pub", pub); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	baseline := filepath.Join(work, "baseline.sig")
	if out, err := runCapture(t, "openshield-fim-baseline", nil,
		"build", "--paths", critical, "--key", key, "--out", baseline); err != nil {
		t.Fatalf("building the baseline: %v\n%s", err, out)
	}

	// THE BASELINE MUST NOT CONTAIN THE FILE CONTENTS. It is a list of hashes of critical files —
	// distributing it must not distribute what is in /etc.
	blob, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(blob), "root ALL=(ALL)") {
		t.Error("the signed baseline CONTAINS the guarded file's content — a baseline is hashes precisely " +
			"so it can be shipped to every node without shipping the files it protects")
	}

	// The ENGINE verifies it against the public half and comes up watching.
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_FIM_PATHS=" + critical,
		"OPENSHIELD_FIM_BASELINE=" + baseline,
		"OPENSHIELD_FIM_BASELINE_PUBKEY=" + pub,
	})
	eng.WaitForOutput("engine observing", 90*time.Second)
	if contains(eng.Output(), "baseline") && contains(eng.Output(), "reject") {
		t.Fatalf("the engine REJECTED a baseline produced by the shipped tool — the signer and the "+
			"verifier disagreeing is the failure this loop exists to rule out\n%s", eng.Output())
	}

	// A baseline signed by an UNTRUSTED key must be refused. Well-formed and correctly signed, just not
	// by the operator — only the signature can tell the difference, which is the whole control.
	otherKey, otherPub := filepath.Join(work, "other.key"), filepath.Join(work, "other.pub")
	if out, err := runCapture(t, "openshield-fim-baseline", nil,
		"keygen", "--out-key", otherKey, "--out-pub", otherPub); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	forged := filepath.Join(work, "forged.sig")
	if out, err := runCapture(t, "openshield-fim-baseline", nil,
		"build", "--paths", critical, "--key", otherKey, "--out", forged); err != nil {
		t.Fatalf("building: %v\n%s", err, out)
	}
	bad := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSNFor(t, "fimbad"),
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer2.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_FIM_PATHS=" + critical,
		"OPENSHIELD_FIM_BASELINE=" + forged,
		"OPENSHIELD_FIM_BASELINE_PUBKEY=" + pub, // the OPERATOR's key, not the one that signed it
	})
	time.Sleep(5 * time.Second)
	out := bad.Output()
	if !contains(out, "baseline") {
		t.Errorf("a baseline signed by an UNTRUSTED key produced no complaint — a node that accepts any "+
			"signed baseline accepts one from whoever compromised the distribution path:\n%s", out)
	}
}

// TestThePrintFilterFailsOpenWhenTheEngineIsUnreachable is the property DLP-2b states most loudly.
//
// A print filter sits in the spooler's chain: a non-zero exit ABORTS the job. That is what makes it
// enforcement — and it is also why the failure mode matters more here than almost anywhere else. A DLP
// that stops an office printing because a daemon died is a DLP that gets uninstalled, which protects
// nothing. So an unreachable engine must let the job through, byte for byte.
func TestThePrintFilterFailsOpenWhenTheEngineIsUnreachable(t *testing.T) {
	work := t.TempDir()
	job := "PostScript-ish job body\nwith a couple of lines\n"
	in := filepath.Join(work, "job.ps")
	if err := os.WriteFile(in, []byte(job), 0o600); err != nil {
		t.Fatal(err)
	}

	// A socket path that nothing is listening on — the "engine is down" case exactly.
	out, err := runCapture(t, "openshield-print-filter", []string{
		"PRINTER=integration-printer",
		"OPENSHIELD_PRINT_SOCKET=" + filepath.Join(work, "absent.sock"),
	}, "1", "alice", "quarterly-report", "1", "", in)
	if err != nil {
		t.Fatalf("the print filter EXITED NON-ZERO with the engine unreachable, which ABORTS THE JOB. "+
			"Fail-open is deliberate here (D17/D73): a DLP that stops an office printing because a daemon "+
			"died is one that gets uninstalled: %v\n%s", err, out)
	}
	// BYTE FOR BYTE. A filter that "passes the job through" while mangling it breaks printing just as
	// thoroughly as one that aborts, and more confusingly.
	if !strings.Contains(out, job) {
		t.Errorf("the job was not copied through unchanged when failing open:\ngot: %q\nwant it to contain: %q",
			out, job)
	}
}
