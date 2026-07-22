package process_test

import (
	"context"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/process"
)

// HIPS-8: the KILL enforcer refuses to kill a critical process, keyed on its TRUSTED identity — the
// real, root-owned executable — NOT the self-settable kernel comm. So a process that merely renames
// itself to a critical name (its exe is not a root-owned critical binary) is still killable, closing
// the "name yourself sshd → unkillable" containment bypass.
func TestKillEnforcerCriticalIdentityIsTrusted(t *testing.T) {
	// The trusted identity of each pid, as the real /proc/<pid>/exe + ownership would report.
	ids := map[int]process.ProcIdentity{
		// Genuine criticals: a root-owned, non-writable binary at a critical basename → SPARED.
		10: {ExePath: "/usr/lib/systemd/systemd", RootOwned: true},
		11: {ExePath: "/usr/sbin/sshd", RootOwned: true},
		12: {ExePath: "/usr/lib/postgresql/16/bin/postgres", RootOwned: true},
		13: {ExePath: "/usr/local/bin/openshield-engine", RootOwned: true}, // the fleet's own binary
		// The containment bypass: a NON-root process names itself sshd; its real exe is in /tmp and is
		// not root-owned → NOT trusted → KILLABLE.
		20: {ExePath: "/tmp/evil/sshd", RootOwned: false},
		// A root-owned but world/group-writable "sshd" is not trusted (an attacker could swap it) → KILLABLE.
		21: {ExePath: "/opt/sshd", RootOwned: true, OtherWritable: true},
		// An ordinary process → KILLABLE.
		22: {ExePath: "/usr/bin/python3", RootOwned: true},
	}
	killed := -1
	enf := process.NewKillEnforcerForTest(999,
		func(pid int) error { killed = pid; return nil },
		func(pid int) (process.ProcIdentity, error) { return ids[pid], nil })

	dec := &corev1.Decision{Action: corev1.Action_ACTION_KILL_PROCESS}

	// Genuine root-owned criticals + the fleet binary are SPARED.
	for _, pid := range []int{10, 11, 12, 13} {
		killed = -1
		if err := enf.EnforceTarget(context.Background(), dec, itoa(pid)); err == nil {
			t.Errorf("killed critical process (pid %d, %s) — HIPS could take down the host/platform", pid, ids[pid].ExePath)
		}
		if killed != -1 {
			t.Errorf("the kill was actually invoked for critical pid %d", pid)
		}
	}

	// The self-renamed non-root process, the writable-binary imposter, and an ordinary process are KILLED.
	for _, pid := range []int{20, 21, 22} {
		killed = -1
		if err := enf.EnforceTarget(context.Background(), dec, itoa(pid)); err != nil {
			t.Errorf("a killable process (pid %d, %s) was refused: %v — a self-renamed process must not gain immunity", pid, ids[pid].ExePath, err)
		}
		if killed != pid {
			t.Errorf("pid %d was not killed (killed=%d) — the trusted-identity guard over-protected it", pid, killed)
		}
	}
}

// The pid≤1 and self-pid guards are unchanged and independent of identity.
func TestKillEnforcerRefusesSelfAndInit(t *testing.T) {
	enf := process.NewKillEnforcerForTest(999,
		func(int) error { t.Fatal("kill must not be invoked for a refused pid"); return nil },
		func(int) (process.ProcIdentity, error) { return process.ProcIdentity{}, nil })
	dec := &corev1.Decision{Action: corev1.Action_ACTION_KILL_PROCESS}
	for _, pid := range []string{"1", "0", "999"} {
		if err := enf.EnforceTarget(context.Background(), dec, pid); err == nil {
			t.Errorf("pid %s was not refused (init/self must always be spared)", pid)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
