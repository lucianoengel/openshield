package meminject

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestMain lets the test binary re-exec itself as an rwx-mapping helper (for the cross-user scan test):
// when MEMINJECT_RWX_HELPER is set it maps a genuine writable+executable region and sleeps, never
// returning to the test framework.
func TestMain(m *testing.M) {
	if os.Getenv("MEMINJECT_RWX_HELPER") != "" {
		p, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC, unix.MAP_ANON|unix.MAP_PRIVATE)
		if err != nil {
			os.Exit(3)
		}
		_ = p
		for {
			time.Sleep(time.Hour)
		}
	}
	os.Exit(m.Run())
}

// TestScanDifferentUserProcessAsRoot is the genuinely ROOT-required path (proven on the VM): a helper
// process owned by a DIFFERENT user maps rwx memory, and only root can read its /proc/<pid>/maps to find
// the W+X region — an unprivileged fleet scan cannot see another user's process. Gated: needs root + a
// low-privilege account to drop to.
func TestScanDifferentUserProcessAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("cross-user memory scan needs root (a fleet-wide scan reads all users' processes)")
	}
	drop, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("no 'nobody' account to drop to: %v", err)
	}
	uid, _ := strconv.Atoi(drop.Uid)
	gid, _ := strconv.Atoi(drop.Gid)

	// Re-exec THIS test binary as 'nobody' in helper mode: it maps rwx and sleeps.
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "MEMINJECT_RWX_HELPER=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the different-user helper: %v", err)
	}
	defer cmd.Process.Kill()
	pid := cmd.Process.Pid
	time.Sleep(400 * time.Millisecond) // let it map + settle

	// As root, scan the OTHER user's process — the W+X region must be visible.
	suspects, err := ScanPID("/proc", pid)
	if err != nil {
		t.Fatalf("root could not read the other user's maps: %v", err)
	}
	if len(suspects) == 0 {
		t.Fatalf("no W+X region found in the injected helper (pid %d, uid %d)", pid, uid)
	}
}
