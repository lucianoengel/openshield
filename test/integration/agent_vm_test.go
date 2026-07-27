//go:build integration

package integration

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// THE PRIVILEGED AGENT, on a real kernel (D300).
//
// `openshield-agent` is the only shipped binary that needs CAP_SYS_ADMIN: it answers fanotify PERMISSION
// events, so it decides — inline, before the exec happens — whether a process may run. Nothing else in
// the suite could touch it, because the build host deliberately has no root, and the whole point of the
// privilege split is that this component is the dangerous one.
//
// So it is ROOT-GATED and runs on a rooted VM, using the same build-here/run-there workflow as the other
// kernel tests: the binaries and the compiled test are copied over, because the VM has no Go toolchain.
// It SKIPS everywhere else — visibly, naming what it needs, rather than passing vacuously.
//
// WHAT IT PROVES that no unit test can: that the shipped binary, run as an operator would run it, turns a
// deny-list entry into an actual EPERM from the kernel. The watchdog, the evaluator and the fanotify
// responder each have their own tests; this is the only thing that proves they are assembled.

func requireRootKernel(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the privileged agent needs root (CAP_SYS_ADMIN for fanotify permission mode) — run this " +
			"scenario on the rooted VM with " + BinDirEnv + " pointing at pre-built binaries")
	}
}

// TestThePrivilegedAgentDeniesAnExecInline is HIPS-3's claim, end to end.
func TestThePrivilegedAgentDeniesAnExecInline(t *testing.T) {
	requireRootKernel(t)
	work := t.TempDir()
	watch := filepath.Join(work, "bin")
	if err := os.MkdirAll(watch, 0o755); err != nil {
		t.Fatal(err)
	}

	// Two real executables in the watched directory: one denied, one not. A test with only the denied
	// one would pass against an agent that denied everything — which is a far more likely bug than one
	// that denies exactly the right thing, and a much worse one to ship.
	copyBin := func(name string) string {
		t.Helper()
		src, err := os.ReadFile("/bin/true")
		if err != nil {
			t.Fatalf("reading /bin/true: %v", err)
		}
		p := filepath.Join(watch, name)
		if err := os.WriteFile(p, src, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	denied := copyBin("denied-tool")
	allowed := copyBin("allowed-tool")

	denyList := filepath.Join(work, "deny.txt")
	if err := os.WriteFile(denyList, []byte(denied+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	agent := Start(t, "openshield-agent", []string{
		"OPENSHIELD_EXEC_MONITOR_DIRS=" + watch,
		"OPENSHIELD_EXEC_DENY=" + denyList,
	})
	agent.WaitForOutput("exec", 60*time.Second)
	// The mark has to be in place before the exec, or the test races the kernel and passes for the
	// wrong reason.
	time.Sleep(2 * time.Second)

	// THE ALLOWED ONE RUNS.
	if err := exec.Command(allowed).Run(); err != nil {
		t.Fatalf("an ALLOWED executable was refused (%v) — an exec gate that denies what it should permit "+
			"is an outage, and the failure operators actually fear\n%s", err, agent.Output())
	}

	// THE DENIED ONE DOES NOT — and the kernel says EPERM, which is how FAN_DENY surfaces to the caller.
	err := exec.Command(denied).Run()
	if err == nil {
		t.Fatalf("a DENIED executable RAN. Inline prevention is the claim HIPS-3 makes that containment "+
			"after the fact does not; without it the process has already done whatever it does\n%s",
			agent.Output())
	}
	if !errors.Is(err, syscall.EPERM) {
		var ee *exec.Error
		if errors.As(err, &ee) && errors.Is(ee.Err, syscall.EPERM) {
			return // exec.Error wrapping EPERM is the same outcome
		}
		t.Errorf("the denied exec failed with %v, want EPERM — a different errno means something other "+
			"than the exec gate refused it, and the test would be proving the wrong thing", err)
	}
}
