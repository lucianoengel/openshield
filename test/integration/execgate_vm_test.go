//go:build integration

package integration

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// APPLICATION WHITELISTING AND THE FAIL-OPEN BUDGET, on a real kernel.
//
// `agent_vm_test.go` proves the deny-list turns into an EPERM. These are the two settings around it that
// carry their own claims and had never been exercised anywhere:
//
//   - `OPENSHIELD_EXEC_ALLOW` is DEFAULT-DENY. It is a strictly stronger and strictly more dangerous
//     posture than a deny-list: everything not named is refused, so the failure mode is not "an attacker
//     ran something" but "the machine stopped working". Both directions have to be shown.
//   - `OPENSHIELD_EXEC_BUDGET` is the fail-open contract (D17/D18). A process blocked in a fanotify
//     permission event is in TASK_UNINTERRUPTIBLE — it cannot be killed, cannot be Ctrl-C'd, and will
//     wait exactly as long as the gate takes. If the gate is slow and the budget does not fire, the host
//     is wedged in a way that survives everything short of a power cycle.
//
// Root-gated: fanotify permission mode needs CAP_SYS_ADMIN in the initial user namespace, so these run
// on the rooted VM via build-here/run-there and SKIP visibly everywhere else.

// execBin copies a real executable into dir under a given name, returning its path.
func execBin(t *testing.T, dir, name string) string {
	t.Helper()
	src, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatalf("reading /bin/true: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, src, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// isEPERM reports whether an exec failed with EPERM, which is how FAN_DENY surfaces to the caller.
// `exec.Error` wraps it, so both shapes count — asserting on only the bare errno made an earlier kernel
// test fail against correct code.
func isEPERM(err error) bool {
	if errors.Is(err, syscall.EPERM) {
		return true
	}
	var ee *exec.Error
	return errors.As(err, &ee) && errors.Is(ee.Err, syscall.EPERM)
}

// TestApplicationWhitelistingRefusesEverythingNotListed (OPENSHIELD_EXEC_ALLOW).
//
// THE PERMITTED HALF IS THE IMPORTANT ONE. A whitelist that refuses everything satisfies "the unlisted
// binary was refused" perfectly, and is an outage — the failure operators actually fear from this
// feature, and the reason default-deny is rarely deployed. So the listed binary must RUN.
func TestApplicationWhitelistingRefusesEverythingNotListed(t *testing.T) {
	requireRootKernel(t)
	work := t.TempDir()
	watch := filepath.Join(work, "bin")
	if err := os.MkdirAll(watch, 0o755); err != nil {
		t.Fatal(err)
	}

	permitted := execBin(t, watch, "permitted-tool")
	unlisted := execBin(t, watch, "unlisted-tool")

	allowList := filepath.Join(work, "allow.txt")
	if err := os.WriteFile(allowList, []byte(permitted+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	agent := Start(t, "openshield-agent", []string{
		"OPENSHIELD_EXEC_MONITOR_DIRS=" + watch,
		"OPENSHIELD_EXEC_ALLOW=" + allowList,
	})
	agent.WaitForOutput("exec", 60*time.Second)
	time.Sleep(2 * time.Second) // the mark must be in place, or the test races the kernel

	if err := exec.Command(permitted).Run(); err != nil {
		t.Fatalf("a WHITELISTED executable was refused (%v). Default-deny that also denies what it "+
			"permits is an outage, and it is the reason this posture is rarely deployed\n%s",
			err, agent.Output())
	}

	err := exec.Command(unlisted).Run()
	if err == nil {
		t.Fatalf("an UNLISTED executable RAN under a whitelist. Default-deny means everything not named "+
			"is refused; a whitelist that only refuses what a deny-list would have caught is a deny-list "+
			"with a more reassuring name\n%s", agent.Output())
	}
	if !isEPERM(err) {
		t.Errorf("the unlisted exec failed with %v, want EPERM — a different errno means something other "+
			"than the exec gate refused it", err)
	}

	// AND THE REST OF THE MACHINE STILL WORKS. This is the assertion that would have caught D330 before
	// it took a VM out: the kernel mark is a MOUNT mark, so without a scope bound the default-deny
	// refuses every executable on the filesystem — `sudo`, `cat`, the login shell — and the host can
	// only be recovered by a power cycle, because stopping the agent needs exec and logging in needs a
	// shell. Measured, not imagined: that is exactly what happened.
	for _, system := range []string{"/bin/true", "/usr/bin/env"} {
		if _, err := os.Stat(system); err != nil {
			continue // not on this image
		}
		if err := exec.Command(system).Run(); err != nil {
			t.Fatalf("%s was refused while an allowlist was active (%v). The whitelist has escaped the "+
				"directories it was pointed at and is refusing the whole mount — which is unrecoverable, "+
				"since undoing it requires executing something\n%s", system, err, agent.Output())
		}
	}
}

// TestASlowVerdictFailsOpenWithinTheBudget (OPENSHIELD_EXEC_BUDGET).
//
// This is the contract that makes inline prevention deployable at all, and the one whose failure is
// worst. A process waiting on a fanotify permission event sits in TASK_UNINTERRUPTIBLE: not killable,
// not interruptible, waiting exactly as long as the gate takes. A gate that hangs does not slow the host
// down — it wedges it, and every subsequent exec joins the queue.
//
// The slow verdict is produced by pointing the gate at an IPC socket that ACCEPTS and never answers,
// which is the realistic shape of the failure (an engine that is up, reachable, and stuck) rather than
// the easy one (an engine that is down). A short budget then has to turn that into an allow.
//
// The assertion is on WALL-CLOCK as well as success: an exec that eventually succeeds after thirty
// seconds is not a fail-open, it is a hang with a happy ending.
func TestASlowVerdictFailsOpenWithinTheBudget(t *testing.T) {
	requireRootKernel(t)
	work := t.TempDir()
	watch := filepath.Join(work, "bin")
	if err := os.MkdirAll(watch, 0o755); err != nil {
		t.Fatal(err)
	}
	tool := execBin(t, watch, "some-tool")

	// A socket that accepts and never replies: the engine is UP and STUCK, which is the case a
	// connection-refused test does not cover.
	sock := SocketPath(t, "hung.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listening on %s: %v", sock, err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c // held open, never answered
		}
	}()

	agent := Start(t, "openshield-agent", []string{
		"OPENSHIELD_EXEC_MONITOR_DIRS=" + watch,
		"OPENSHIELD_EXEC_DENY=" + writeEmptyDenyList(t, work),
		"OPENSHIELD_EXEC_IPC_SOCKET=" + sock,
		"OPENSHIELD_EXEC_IPC_TIMEOUT=500ms",
		"OPENSHIELD_EXEC_BUDGET=1s",
	})
	agent.WaitForOutput("exec", 60*time.Second)
	time.Sleep(2 * time.Second)

	start := time.Now()
	runErr := exec.Command(tool).Run()
	elapsed := time.Since(start)

	if runErr != nil {
		t.Fatalf("the exec was REFUSED (%v) because the engine did not answer. Failing CLOSED here means "+
			"a stuck engine stops every process on the host — the one outcome ADR-8 forbids, and the "+
			"reason this feature can be deployed at all\n%s", runErr, agent.Output())
	}
	// Generous against a loaded VM, but far below the "no budget at all" case, which never returns.
	if elapsed > 15*time.Second {
		t.Errorf("the exec took %s to fail open against a budget of 1s. An exec that eventually succeeds "+
			"is not a fail-open, it is a hang with a happy ending — and the process was in "+
			"TASK_UNINTERRUPTIBLE for all of it", elapsed)
	}
	t.Logf("failed open in %s with the engine hung", elapsed)
}

// writeEmptyDenyList gives the agent a signal source so it starts: it refuses to run with no exec signal
// configured at all, deliberately, rather than coming up as a do-nothing process.
func writeEmptyDenyList(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(p, []byte("# no entries — the verdict comes from the engine over IPC\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestABinaryCreatedAfterStartupIsStillRefused is the assertion that makes narrowing the kernel mark
// safe rather than clever (D331).
//
// With per-file marks the agent covers what existed when it started. A binary dropped into a watched
// directory afterwards is unmarked, produces NO permission event, and under default-deny therefore RUNS
// — which is a better outcome for an attacker than being allowed, because the execution is also
// invisible. An inotify watch marks it as it appears; this is what proves the watch is wired and works
// on a real kernel rather than in a unit test's imagination.
func TestABinaryCreatedAfterStartupIsStillRefused(t *testing.T) {
	requireRootKernel(t)
	work := t.TempDir()
	watch := filepath.Join(work, "bin")
	if err := os.MkdirAll(watch, 0o755); err != nil {
		t.Fatal(err)
	}
	permitted := execBin(t, watch, "permitted-tool")

	allowList := filepath.Join(work, "allow.txt")
	if err := os.WriteFile(allowList, []byte(permitted+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	agent := Start(t, "openshield-agent", []string{
		"OPENSHIELD_EXEC_MONITOR_DIRS=" + watch,
		"OPENSHIELD_EXEC_ALLOW=" + allowList,
	})
	agent.WaitForOutput("mark=per-file", 60*time.Second)
	time.Sleep(2 * time.Second)

	// The agent is up and narrow. NOW drop a binary in — the move an attacker makes.
	dropped := execBin(t, watch, "dropped-tool")
	time.Sleep(2 * time.Second) // let the watcher mark it

	err := exec.Command(dropped).Run()
	if err == nil {
		t.Fatalf("a binary CREATED AFTER the agent started RAN under an allowlist. Narrowing the kernel "+
			"mark without marking new files turns an optimisation into a bypass — and a better one than "+
			"being allowed, because the exec raises no event at all\n%s", agent.Output())
	}
	if !isEPERM(err) {
		t.Errorf("the dropped binary failed with %v, want EPERM", err)
	}

	// And the allowlisted one still runs, so this cannot pass by refusing everything.
	if err := exec.Command(permitted).Run(); err != nil {
		t.Errorf("the allowlisted binary was refused (%v) after the watcher ran\n%s", err, agent.Output())
	}
}

// TestAMovedInBinaryIsStillRefused covers the other way a binary arrives: built elsewhere, then moved
// into place. A create-only watch would miss it, and "mv" is the more likely of the two.
func TestAMovedInBinaryIsStillRefused(t *testing.T) {
	requireRootKernel(t)
	work := t.TempDir()
	watch := filepath.Join(work, "bin")
	staging := filepath.Join(work, "staging")
	for _, d := range []string{watch, staging} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	permitted := execBin(t, watch, "permitted-tool")
	allowList := filepath.Join(work, "allow.txt")
	if err := os.WriteFile(allowList, []byte(permitted+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	agent := Start(t, "openshield-agent", []string{
		"OPENSHIELD_EXEC_MONITOR_DIRS=" + watch,
		"OPENSHIELD_EXEC_ALLOW=" + allowList,
	})
	agent.WaitForOutput("mark=per-file", 60*time.Second)
	time.Sleep(2 * time.Second)

	built := execBin(t, staging, "moved-tool")
	moved := filepath.Join(watch, "moved-tool")
	if err := os.Rename(built, moved); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)

	if err := exec.Command(moved).Run(); err == nil {
		t.Fatalf("a binary MOVED into a watched directory RAN under an allowlist\n%s", agent.Output())
	}
}
