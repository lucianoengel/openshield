//go:build linux

package execmon_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/lucianoengel/openshield/internal/agent/execmon"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// requireExecPerm skips unless this is a root Linux host whose kernel supports fanotify
// permission mode (FAN_CLASS_CONTENT). Gated like the swtpm/Postgres tests: it runs on a
// rooted VM and in a privileged CI job, and is skipped everywhere else.
func requireExecPerm(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("execmon kernel test needs root (CAP_SYS_ADMIN for fanotify permission mode)")
	}
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC, unix.O_RDONLY)
	if err != nil {
		t.Skipf("fanotify permission mode unavailable: %v", err)
	}
	unix.Close(fd)
}

// copyExec copies /bin/true to dst with an exec bit, so the test execs a real binary from
// the marked directory (mtime/inode irrelevant — the mark is on the dir).
func copyExec(t *testing.T, dst string) {
	t.Helper()
	src, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatalf("reading /bin/true: %v", err)
	}
	if err := os.WriteFile(dst, src, 0o755); err != nil {
		t.Fatal(err)
	}
}

func fdCount(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// TestExecPermissionKernelBlocksDeniedExec is the real proof (HIPS-3): with the monitor
// running against a real kernel, a deny-listed binary executed from the watched dir is
// REFUSED by the kernel (execve → EACCES/EPERM), while a benign binary in the same dir runs.
// It also asserts the producer does not leak fds across repeated execs.
//
// Mutation (the producer answers FAN_ALLOW for a Block verdict): the denied binary RUNS →
// this test FAILs on "want the denied exec to be refused".
func TestExecPermissionKernelBlocksDeniedExec(t *testing.T) {
	requireExecPerm(t)
	dir := t.TempDir()
	denied := filepath.Join(dir, "backdoor")
	benign := filepath.Join(dir, "helper")
	copyExec(t, denied)
	copyExec(t, benign)

	mon, err := execmon.Open([]string{dir})
	if err != nil {
		t.Fatalf("open monitor: %v", err)
	}
	defer mon.Close()

	wd := &watchdog.Watchdog{
		SelfPID:   int32(os.Getpid()),
		Budget:    2 * time.Second,
		Responder: watchdog.FanotifyResponder{NotifyFD: mon.NotifyFD()},
		Evaluator: execmon.DenyEvaluator{DenyBasenames: map[string]bool{"backdoor": true}},
		Audit:     func(context.Context, watchdog.PermissionEvent, watchdog.Severity, string) error { return nil },
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = mon.Run(ctx, wd); close(done) }()
	time.Sleep(150 * time.Millisecond) // let the reader reach its poll

	fdsBefore := fdCount(t)

	// The benign binary runs (allowed).
	if out, err := exec.Command(benign).CombinedOutput(); err != nil {
		t.Fatalf("benign exec was refused (%v): %s", err, out)
	}

	// The deny-listed binary is refused by the kernel.
	if err := exec.Command(denied).Run(); err == nil {
		t.Fatal("the deny-listed binary EXECUTED — inline exec prevention did not block it")
	} else if !isPermission(err) {
		t.Fatalf("denied exec failed with %v, want a permission error (EACCES/EPERM)", err)
	}

	// Run several more execs, then confirm no fd leak in the monitor's process.
	for i := 0; i < 8; i++ {
		_ = exec.Command(benign).Run()
		_ = exec.Command(denied).Run()
	}
	if fdsAfter := fdCount(t); fdsAfter > fdsBefore+4 {
		t.Errorf("fd count grew %d → %d across execs — the producer leaks event fds", fdsBefore, fdsAfter)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("monitor did not stop on context cancel")
	}
}

// isPermission reports whether an exec error is a permission denial (the fanotify DENY
// surfaces as EACCES; some kernels/paths surface EPERM).
func isPermission(err error) bool {
	if os.IsPermission(err) {
		return true
	}
	if ee, ok := err.(*exec.Error); ok {
		return ee.Err == unix.EACCES || ee.Err == unix.EPERM
	}
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err == unix.EACCES || pe.Err == unix.EPERM
	}
	return false
}

// TestExecPermissionKernelAllowlist (HIPS-4 application whitelisting): with a default-deny allowlist,
// a NON-allowlisted binary is kernel-REFUSED, while an allowlisted one runs.
//
// NOTE: the kernel raises FAN_OPEN_EXEC_PERM for the dynamic LOADER (ld-linux) too, not just the main
// binary — so a real allowlist MUST include the loader (and any script interpreters), or every dynamic
// binary breaks. The allowlist here includes the common loader basenames for that reason; a
// non-allowlisted main binary is still blocked at its OWN exec (before the loader is reached).
func TestExecPermissionKernelAllowlist(t *testing.T) {
	requireExecPerm(t)
	dir := t.TempDir()
	allowed := filepath.Join(dir, "helper")
	blocked := filepath.Join(dir, "unlisted")
	copyExec(t, allowed)
	copyExec(t, blocked)

	mon, err := execmon.Open([]string{dir})
	if err != nil {
		t.Fatalf("open monitor: %v", err)
	}
	defer mon.Close()

	allow := map[string]bool{
		"helper": true,
		// The dynamic loader must be allowlisted or a dynamic binary cannot run.
		"ld-linux-x86-64.so.2": true, "ld-linux.so.2": true, "ld-musl-x86_64.so.1": true,
	}
	wd := &watchdog.Watchdog{
		SelfPID:   int32(os.Getpid()),
		Budget:    2 * time.Second,
		Responder: watchdog.FanotifyResponder{NotifyFD: mon.NotifyFD()},
		Evaluator: execmon.DenyEvaluator{AllowBasenames: allow}, // default-deny
		Audit:     func(context.Context, watchdog.PermissionEvent, watchdog.Severity, string) error { return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = mon.Run(ctx, wd) }()
	time.Sleep(150 * time.Millisecond)

	// The allowlisted binary runs (its own exec + the loader are both allowlisted).
	if out, err := exec.Command(allowed).CombinedOutput(); err != nil {
		t.Fatalf("allowlisted binary was refused (%v): %s", err, out)
	}
	// The non-allowlisted binary is refused at its own exec (default-deny), before the loader.
	if err := exec.Command(blocked).Run(); err == nil {
		t.Fatal("a non-allowlisted binary EXECUTED — application whitelisting did not default-deny it")
	} else if !isPermission(err) {
		t.Fatalf("blocked exec failed with %v, want a permission error (EACCES/EPERM)", err)
	}
}
