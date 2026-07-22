//go:build linux

package process

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// HIPS-7: platformKill revalidates the observation-time start-time. A mismatched start-time is exactly
// what a recycled pid looks like, so it is the deterministic stand-in for "the pid was reused" — the
// live process MUST be spared; with the correct start-time it IS killed. A background Wait reaps the
// child so a real kill becomes an observable exit (a SIGKILL'd-but-unreaped zombie would otherwise
// still answer kill(pid,0), hiding a kill).
func TestPlatformKillRevalidatesStartTicks(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sleep: %v", err)
	}
	pid := cmd.Process.Pid
	exited := make(chan *os.ProcessState, 1)
	go func() { st, _ := cmd.Process.Wait(); exited <- st }()
	defer cmd.Process.Kill() // best-effort cleanup if the test fails before the correct-kill

	real := readStartTicksLinux(pid)
	if real == 0 {
		t.Fatalf("could not read start-ticks for the spawned pid %d", pid)
	}

	// Mismatched captured identity (a recycled pid) → the live process is SPARED: it must NOT exit.
	if err := platformKill(pid, real+1); err != nil {
		t.Fatalf("platformKill with a mismatched start-time returned an error: %v", err)
	}
	select {
	case <-exited:
		t.Fatal("the process exited after a mismatched-start-time kill — the pid-reuse guard failed to spare it")
	case <-time.After(500 * time.Millisecond):
		// still running after a grace period — correctly spared
	}

	// Correct captured identity → it IS terminated (the background Wait observes the exit).
	if err := platformKill(pid, real); err != nil {
		t.Fatalf("platformKill with the correct start-time returned an error: %v", err)
	}
	select {
	case st := <-exited:
		if ws, ok := st.Sys().(syscall.WaitStatus); ok && !ws.Signaled() {
			t.Errorf("the process exited without being signaled (%v) — the correct-identity kill did not fire", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the process survived a correct-identity kill")
	}
}

// Sanity: readStartTicksLinux reads a non-zero, stable value for the running process.
func TestReadStartTicksLinuxSelf(t *testing.T) {
	a := readStartTicksLinux(os.Getpid())
	if a == 0 {
		t.Fatal("readStartTicksLinux(self) returned 0")
	}
	if b := readStartTicksLinux(os.Getpid()); b != a {
		t.Errorf("readStartTicksLinux(self) unstable: %d then %d", a, b)
	}
}
