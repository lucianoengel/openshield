package prefilter_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/prefilter"
	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

func buildWorker(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "openshield-worker")
	out, err := exec.Command("go", "build", "-o", bin, "../../../cmd/openshield-worker").CombinedOutput()
	if err != nil {
		t.Fatalf("building worker: %v\n%s", err, out)
	}
	return bin
}

// An inline-prevention access policy: BLOCK a checksum-backed PII hit at high
// confidence (the two-tier prefilter's tier-1 uses exactly this to inline-deny).
const blockOnCPF = `package openshield
import rego.v1
hit if { some h in input.classification; h.type == "DETECTOR_TYPE_CPF"; h.confidence >= 0.85 }
decision := {"action":"BLOCK","reason":"checksum-backed PII in prefix"} if { hit }
decision := {"action":"ALLOW","reason":"no PII in prefix"} if { not hit }`

// The tier-1 substrate PROVEN with the REAL worker: a bounded prefix containing a CPF
// is parsed IN the worker, the OPA policy decides BLOCK at high confidence, and the
// decider returns that Decision with NO audit write. This is the synchronous tier of
// inline prevention, real end to end except the kernel permission syscall (D52).
func TestDeciderRealWorkerBlocksCPFInPrefix(t *testing.T) {
	ctx := context.Background()
	worker, err := privileged.StartWorker(ctx, buildWorker(t))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	pol, err := policy.New(ctx, "block-cpf", "1", blockOnCPF)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "customers.csv")
	if err := os.WriteFile(file, []byte("name,cpf\nalice,111.444.777-35\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := prefilter.NewDecider(worker, pol, 0, 5*time.Second, nil)
	dec, err := d.DecidePartial(ctx, watchdog.PermissionEvent{PID: 42, Path: file})
	if err != nil {
		t.Fatalf("DecidePartial: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_BLOCK {
		t.Fatalf("decision = %v, want BLOCK (a CPF in the prefix must inline-deny)", dec.GetAction())
	}
	if dec.GetConfidence() < 0.85 {
		t.Errorf("confidence = %v, want ≥ 0.85 (a checksum-backed hit is high-confidence)", dec.GetConfidence())
	}

	// A clean file → ALLOW (no inline block on a file without PII).
	clean := filepath.Join(dir, "readme.txt")
	if err := os.WriteFile(clean, []byte("just some text, nothing sensitive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cdec, err := d.DecidePartial(ctx, watchdog.PermissionEvent{PID: 42, Path: clean})
	if err != nil {
		t.Fatal(err)
	}
	if cdec.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Errorf("clean file decision = %v, want ALLOW", cdec.GetAction())
	}
}

// End to end: the Decider wired into the PreFilter and the REAL watchdog — a CPF file
// drives an inline kernel DENY (a legitimate open would be prevented), while the async
// full-file job is still submitted. This is the whole two-tier mechanism minus the
// permission syscall the environment cannot grant (D52).
func TestDeciderDrivesInlineDenyThroughWatchdog(t *testing.T) {
	ctx := context.Background()
	worker, err := privileged.StartWorker(ctx, buildWorker(t))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	pol, err := policy.New(ctx, "block-cpf", "1", blockOnCPF)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "leak.csv")
	if err := os.WriteFile(file, []byte("cpf\n111.444.777-35\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := prefilter.NewDecider(worker, pol, 0, 5*time.Second, nil)
	sub := &recSubmitter{}
	pf := prefilter.New(d, sub, 0.9, nil)
	resp := &recResponder{}
	wd := &watchdog.Watchdog{SelfPID: 1, Budget: 6 * time.Second, Responder: resp, Evaluator: pf}

	if err := wd.Handle(ctx, watchdog.PermissionEvent{PID: 42, Path: file}); err != nil {
		t.Fatal(err)
	}
	if !resp.denied {
		t.Error("a CPF file did not drive an inline kernel DENY — prevention did not fire")
	}
	if len(sub.got) != 1 {
		t.Errorf("async submissions = %d, want 1 (full-file classification still runs)", len(sub.got))
	}
}

// The bound is real: a CPF placed PAST the prefix ceiling is NOT seen by the
// synchronous tier (it reads only maxBytes), so the decision is ALLOW — the hit is left
// to the async full-file tier. This is the explicit two-tier trade-off, proven, not
// assumed: inline prevention sees only the prefix; deep content is contained async.
func TestDeciderPrefixBoundIsReal(t *testing.T) {
	ctx := context.Background()
	worker, err := privileged.StartWorker(ctx, buildWorker(t))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	pol, err := policy.New(ctx, "block-cpf", "1", blockOnCPF)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "deep.csv")
	// 200 bytes of filler, THEN the CPF — beyond a 64-byte prefix.
	content := strings.Repeat("x", 200) + "\n111.444.777-35\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	d := prefilter.NewDecider(worker, pol, 64, 5*time.Second, nil) // 64-byte prefix
	dec, err := d.DecidePartial(ctx, watchdog.PermissionEvent{PID: 42, Path: file})
	if err != nil {
		t.Fatal(err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Errorf("decision = %v, want ALLOW — a CPF past the prefix must NOT be seen inline (unbounded read?)", dec.GetAction())
	}
}

func TestDeciderMissingPathErrors(t *testing.T) {
	d := prefilter.NewDecider(nil, nil, 0, 0, nil)
	// The empty-path guard gives its OWN error (not a generic open failure), so the
	// caller can distinguish a malformed event from an unreadable file.
	if _, err := d.DecidePartial(context.Background(), watchdog.PermissionEvent{Path: ""}); err == nil || !strings.Contains(err.Error(), "no path to classify") {
		t.Errorf("empty path: err = %v, want the 'no path to classify' guard", err)
	}
	// A non-existent file surfaces the open error (fail-open is the prefilter's job).
	if _, err := d.DecidePartial(context.Background(), watchdog.PermissionEvent{Path: filepath.Join(t.TempDir(), "nope")}); err == nil || !strings.Contains(err.Error(), "opening") {
		t.Errorf("missing file: err = %v, want an opening error", err)
	}
}
