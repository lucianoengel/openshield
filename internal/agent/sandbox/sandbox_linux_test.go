//go:build linux

package sandbox_test

import (
	"os"
	"os/exec"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/lucianoengel/openshield/internal/agent/sandbox"
)

// Applying seccomp is irreversible for the process, so these run in a
// subprocess: the test binary re-execs itself with a mode env var, the child
// applies the sandbox and probes a socket, and the parent asserts the child's
// exit code. Doing it in-process would poison every test that ran afterwards.
func TestSocketDeniedAfterApply(t *testing.T) {
	if !seccompProbablyAvailable(t) {
		t.Skipf("LOUD SKIP: seccomp unavailable in this environment; the network-deny " +
			"sandbox is NOT verified by this run")
	}
	out, err := runChild(t, "socket-after-apply")
	if err != nil {
		t.Fatalf("child failed unexpectedly: %v\n%s", err, out)
	}
	if string(out) != "denied\n" {
		t.Errorf("child said %q, want %q — socket() was not blocked after the sandbox applied", out, "denied")
	}
}

func TestFilterCoversAllThreads(t *testing.T) {
	if !seccompProbablyAvailable(t) {
		t.Skip("LOUD SKIP: seccomp unavailable; thread-coverage NOT verified")
	}
	out, err := runChild(t, "socket-from-goroutine")
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	if string(out) != "denied\n" {
		t.Errorf("child said %q, want %q — a goroutine on another thread bypassed the filter", out, "denied")
	}
}

// The child entry point. Runs when OPENSHIELD_SANDBOX_CHILD is set, applies the
// sandbox, performs the requested probe, prints "denied"/"allowed", and exits.
func TestMain(m *testing.M) {
	switch os.Getenv("OPENSHIELD_SANDBOX_CHILD") {
	case "socket-after-apply":
		os.Exit(childSocket(false))
	case "socket-from-goroutine":
		os.Exit(childSocket(true))
	case "apply-only":
		// Availability probe: can seccomp be loaded AT ALL in this environment?
		// Deliberately independent of whether socket is denied — otherwise an
		// availability check that shares the tested outcome would turn a broken
		// filter (empty denylist) into a skip instead of a failure, masking the
		// very regression the socket test exists to catch.
		if err := sandbox.Apply(); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(3)
		}
		os.Stdout.WriteString("applied\n")
		os.Exit(0)
	default:
		os.Exit(m.Run())
	}
}

func childSocket(fromGoroutine bool) int {
	if err := sandbox.Apply(); err != nil {
		os.Stderr.WriteString("apply: " + err.Error() + "\n")
		return 3
	}
	probe := func() int {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if err != nil {
			os.Stdout.WriteString("denied\n")
			return 0
		}
		unix.Close(fd)
		os.Stdout.WriteString("allowed\n")
		return 1
	}
	if !fromGoroutine {
		return probe()
	}
	var wg sync.WaitGroup
	var code int
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Nudge the scheduler so this likely runs on a different OS thread.
		code = probe()
	}()
	wg.Wait()
	return code
}

func runChild(t *testing.T, mode string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", "TestMain")
	cmd.Env = append(os.Environ(), "OPENSHIELD_SANDBOX_CHILD="+mode)
	return cmd.CombinedOutput()
}

// seccompProbablyAvailable checks whether seccomp can be LOADED at all — not
// whether socket is denied. Some CI kernels block seccomp entirely, and that
// must be a loud skip; but a filter that loads yet fails to deny is a FAILURE,
// so the availability probe must not depend on the denial outcome.
func seccompProbablyAvailable(t *testing.T) bool {
	t.Helper()
	out, err := runChild(t, "apply-only")
	return err == nil && string(out) == "applied\n"
}
