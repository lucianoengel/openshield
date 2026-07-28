//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/execipc"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// THE EXEC-VERDICT SOCKET (HIPS-3 increment 2a), from the far side.
//
// The privileged gate holds CAP_SYS_ADMIN and, by design, cannot parse anything — so it asks the
// unprivileged engine, which owns the policy, whether an exec may proceed. That question crosses a unix
// socket, and `OPENSHIELD_EXEC_IPC_SOCKET` is what puts the answering end of it in the running engine.
//
// The gate itself needs a live kernel and root, and its scenarios are VM-gated. The ANSWERING side does
// not: a unix socket is a unix socket. So these speak the real protocol to the real engine with the real
// policy, unprivileged — which is worth doing, because the one defect this path has already had (D301)
// was on exactly this side. Exec events were built without provenance, every decision failed validation,
// the watchdog fail-opened, and the agent went on logging "inline exec prevention ACTIVE" while denying
// nothing at all. A test that asks the engine for a verdict is what makes that unrepeatable.

// denyExec refuses one specific binary and permits everything else. Both halves are needed: a policy
// that denied every exec would make the DENY assertion pass while proving nothing, and an inline gate
// that denies everything is indistinguishable from a broken machine.
const denyExec = `package openshield
import rego.v1
denied if { input.event.exec_path == "/usr/local/bin/not-allowed-here" }
decision := {"action":"DENY_EXEC","reason":"not on the allowlist"} if { denied }
decision := {"action":"ALLOW","reason":"permitted"} if { not denied }`

// TestTheEngineAnswersExecVerdictsOverTheIpcSocket.
func TestTheEngineAnswersExecVerdictsOverTheIpcSocket(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	// A SHORT socket path — see SocketPath. A `t.TempDir()` address embeds the test's NAME and overruns
	// the kernel's limit, after which the engine fails to listen for a reason that has nothing to do with
	// what is under test.
	sock := SocketPath(t, "v.sock")
	policy := filepath.Join(work, "exec.rego")
	if err := os.WriteFile(policy, []byte(denyExec), 0o600); err != nil {
		t.Fatal(err)
	}

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
		"OPENSHIELD_EXEC_IPC_SOCKET=" + sock,
	})
	eng.WaitForOutput("exec-verdict IPC ACTIVE", 90*time.Second)
	Eventually(t, 30*time.Second, "the verdict socket to accept connections", func() bool {
		_, err := os.Stat(sock)
		return err == nil
	})

	ask := func(path string) watchdog.Verdict {
		t.Helper()
		// A FRESH CLIENT PER QUESTION. The client caches a verdict per path and opens a circuit breaker
		// after repeated failures; reusing one across the two questions would mean the second answer
		// might never have left this process.
		c := execipc.NewClient(sock)
		defer c.Close()
		v, err := c.Evaluate(Ctx(t), watchdog.PermissionEvent{PID: 4242, FD: -1, Path: path})
		if err != nil {
			t.Fatalf("asking the engine about %s: %v\n%s", path, err, eng.Output())
		}
		return v
	}

	if v := ask("/usr/local/bin/not-allowed-here"); v != watchdog.VerdictBlock {
		t.Errorf("the engine answered ALLOW for a binary its policy DENIES. The gate cannot decide this "+
			"itself — it holds no parser and no policy — so an engine that answers allow here is an "+
			"application-whitelisting feature that whitelists everything\n%s", eng.Output())
	}
	if v := ask("/bin/ls"); v != watchdog.VerdictAllow {
		t.Errorf("the engine answered BLOCK for a permitted binary. An inline gate that refuses "+
			"everything is not prevention, it is an outage\n%s", eng.Output())
	}
}

// TestAnExecVerdictSurvivesTheEngineGoingAway is the fail-open contract at the transport (D18/ADR-8).
//
// This is the property that decides whether the feature is deployable at all. The gate sits in the exec
// path of every process on the host, so an engine that is stopped, upgraded or crashed must degrade to
// ALLOW — and it must do so by an EXPLICIT decision the client makes, with a reason an operator can
// read, not by a timeout somewhere that happens to end in the same place.
//
// The engine is stopped rather than made slow, because "stopped" is the case a deployment meets on every
// upgrade, and it is the one where a wrong answer wedges the machine.
func TestAnExecVerdictSurvivesTheEngineGoingAway(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	sock := SocketPath(t, "v.sock")
	policy := filepath.Join(work, "exec.rego")
	if err := os.WriteFile(policy, []byte(denyExec), 0o600); err != nil {
		t.Fatal(err)
	}

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
		"OPENSHIELD_EXEC_IPC_SOCKET=" + sock,
	})
	eng.WaitForOutput("exec-verdict IPC ACTIVE", 90*time.Second)
	Eventually(t, 30*time.Second, "the verdict socket to accept connections", func() bool {
		_, err := os.Stat(sock)
		return err == nil
	})

	// FIRST, THE DENIAL WORKS. Without this the scenario would be satisfied by a client that always
	// allows, which is the failure it is meant to rule out.
	live := execipc.NewClient(sock)
	v, err := live.Evaluate(Ctx(t), watchdog.PermissionEvent{PID: 1, FD: -1, Path: "/usr/local/bin/not-allowed-here"})
	if err != nil || v != watchdog.VerdictBlock {
		t.Fatalf("the engine did not deny before the outage (verdict=%v err=%v) — the fail-open half of "+
			"this scenario would then prove nothing\n%s", v, err, eng.Output())
	}
	live.Close()

	eng.Stop()

	// A NEW client, so no cached verdict can answer for the dead engine.
	dead := execipc.NewClient(sock)
	defer dead.Close()
	got, err := dead.Evaluate(Ctx(t), watchdog.PermissionEvent{PID: 2, FD: -1, Path: "/usr/local/bin/not-allowed-here"})
	if got != watchdog.VerdictAllow {
		t.Errorf("with the engine STOPPED the gate answered %v for a path the policy denies. Failing "+
			"CLOSED here means an engine crash, or an ordinary upgrade, stops every exec on the host — "+
			"the security product becomes the outage", got)
	}
	if err == nil {
		t.Error("the fail-open was SILENT. An allow granted because nothing could be asked is not the " +
			"same as an allow the policy decided, and the watchdog audits the difference only if the " +
			"transport reports it (D18: a timeout-allow is a high-severity event, never silence)")
	}
}
