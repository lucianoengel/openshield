//go:build linux

package sandbox_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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

func TestEveryDeniedSyscallIsActuallyDenied(t *testing.T) {
	if !seccompProbablyAvailable(t) {
		t.Skip("LOUD SKIP: seccomp unavailable; the denylist is NOT verified by this run")
	}
	out, err := runChild(t, "denied-family")
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "all denied" {
		t.Errorf("%s\n\nEach name listed reached the kernel despite being on deniedSyscalls. socket() being "+
			"blocked is not the whole property: sendmsg/sendto can still use an INHERITED descriptor, and "+
			"ptrace/process_vm_readv are how a compromised worker would read the privileged agent's memory.", got)
	}
}

// Guards the direction the denial tests cannot: that the sandbox has not simply bricked the worker.
func TestTheWorkerCanStillDoItsJobAfterTheSandboxApplies(t *testing.T) {
	if !seccompProbablyAvailable(t) {
		t.Skip("LOUD SKIP: seccomp unavailable; NOT verified by this run")
	}
	out, err := runChild(t, "work-still-possible")
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "work possible" {
		t.Errorf("after applying the sandbox the worker could not read a file: %s\n\n"+
			"Every other test here asserts that something was REFUSED, so a filter denying everything "+
			"would satisfy all of them while making the parser worker useless.", got)
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
	case "denied-family":
		os.Exit(childDeniedFamily())
	case "work-still-possible":
		os.Exit(childWorkStillPossible())
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

// THE DENYLIST HAS FIFTEEN ENTRIES AND ONE OF THEM WAS VERIFIED.
//
// `socket` being blocked is the headline, but it is not the whole property. A parser RCE that cannot call
// socket() can still write to a file descriptor it inherited (sendmsg/sendto), and `ptrace` /
// process_vm_readv are not about egress at all — they are how a compromised worker would read or rewrite
// another process's memory, including the privileged agent's. Every name in the list is there because
// something in the threat model needs it gone, so every name is probed.
//
// Each syscall is invoked with zero arguments, which is safe and sufficient: seccomp's ActionErrno rejects
// on the syscall NUMBER before any argument is examined, so a denied call returns EPERM regardless of what
// it was passed, while a permitted one gets far enough to fail for its own reasons (EINVAL, EFAULT, EBADF).
// That makes EPERM-or-not a clean, argument-independent signal.
func childDeniedFamily() int {
	if err := sandbox.Apply(); err != nil {
		os.Stderr.WriteString("apply: " + err.Error() + "\n")
		return 3
	}
	// accept (not accept4) is deliberately absent: it does not exist on linux/arm64, and a probe that
	// fails to compile on one architecture is worse than one that covers the portable name.
	denied := []struct {
		name string
		trap uintptr
	}{
		{"socket", unix.SYS_SOCKET},
		{"socketpair", unix.SYS_SOCKETPAIR},
		{"connect", unix.SYS_CONNECT},
		{"bind", unix.SYS_BIND},
		{"listen", unix.SYS_LISTEN},
		{"accept4", unix.SYS_ACCEPT4},
		{"sendto", unix.SYS_SENDTO},
		{"recvfrom", unix.SYS_RECVFROM},
		{"sendmsg", unix.SYS_SENDMSG},
		{"recvmsg", unix.SYS_RECVMSG},
		{"ptrace", unix.SYS_PTRACE},
		{"process_vm_readv", unix.SYS_PROCESS_VM_READV},
		{"process_vm_writev", unix.SYS_PROCESS_VM_WRITEV},
	}
	var escaped []string
	for _, d := range denied {
		if _, _, errno := unix.Syscall(d.trap, 0, 0, 0); errno != unix.EPERM {
			escaped = append(escaped, d.name+"("+errno.Error()+")")
		}
	}
	if len(escaped) > 0 {
		os.Stdout.WriteString("escaped: " + strings.Join(escaped, " ") + "\n")
		return 0
	}
	os.Stdout.WriteString("all denied\n")
	return 0
}

// A FILTER THAT DENIES EVERYTHING WOULD PASS EVERY TEST ABOVE.
//
// The denial tests only ever assert that something was refused, so an empty allowlist, a broken policy, or
// a default action of ActionErrno would satisfy all of them while making the worker useless — it could no
// longer open, read or parse the files it exists to classify. This probes the other direction: after the
// sandbox is applied the worker must still be able to do its job.
func childWorkStillPossible() int {
	if err := sandbox.Apply(); err != nil {
		os.Stderr.WriteString("apply: " + err.Error() + "\n")
		return 3
	}
	if _, _, errno := unix.Syscall(unix.SYS_GETPID, 0, 0, 0); errno != 0 {
		os.Stdout.WriteString("getpid failed: " + errno.Error() + "\n")
		return 0
	}
	dir, err := os.MkdirTemp("", "sandbox-work")
	if err != nil {
		os.Stdout.WriteString("mkdir failed: " + err.Error() + "\n")
		return 0
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "scan-me.txt")
	if err := os.WriteFile(p, []byte("CPF 529.982.247-25"), 0o600); err != nil {
		os.Stdout.WriteString("write failed: " + err.Error() + "\n")
		return 0
	}
	b, err := os.ReadFile(p)
	if err != nil {
		os.Stdout.WriteString("read failed: " + err.Error() + "\n")
		return 0
	}
	if string(b) != "CPF 529.982.247-25" {
		os.Stdout.WriteString("content mismatch\n")
		return 0
	}
	os.Stdout.WriteString("work possible\n")
	return 0
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
//
// IT ALSO HAS TO DISTINGUISH "NO SECCOMP HERE" FROM "OUR FILTER IS BROKEN", and the first version did not.
// Setting DefaultAction to ActionErrno — deny everything — makes the child die on a SIGNAL the moment the
// filter loads, because the Go runtime cannot make the syscalls it needs to reach the next line. The probe
// saw a failed child, reported "unavailable", and EVERY TEST IN THIS FILE SKIPPED. A filter so broken it
// kills the process it protects produced a green run.
//
// That is the same shape as the comment above it warns about, one level further out: the availability
// check must not be satisfiable by the failure it is meant to detect. So the two outcomes are now told
// apart by HOW the child died:
//
//   - a clean exit 3, meaning Apply() returned an error (ErrUnsupported on a kernel without seccomp)
//     — genuinely unavailable, skip loudly.
//   - death by signal — the filter loaded and then killed its own process. That is a FAILURE, always,
//     and it is never a reason to skip.
func seccompProbablyAvailable(t *testing.T) bool {
	t.Helper()
	out, err := runChild(t, "apply-only")
	if err == nil && strings.TrimSpace(string(out)) == "applied" {
		return true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			t.Fatalf("the sandbox child was killed by signal %v after loading the filter.\n"+
				"This is a BROKEN FILTER, not a kernel without seccomp — the sandbox killed the process it "+
				"is supposed to be protecting. Reporting it as 'unavailable' would skip every test in this "+
				"file and call the run green.\nchild output: %s", ws.Signal(), out)
		}
		if ee.ExitCode() == 3 {
			return false // Apply() returned an error of its own accord; genuinely unsupported here.
		}
	}
	t.Fatalf("the sandbox availability probe failed in a way that is neither 'unsupported' nor a signal "+
		"death, so it cannot be classified: %v\noutput: %s", err, out)
	return false
}
