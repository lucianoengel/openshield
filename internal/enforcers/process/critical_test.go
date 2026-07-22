package process_test

import (
	"context"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/process"
)

// HIPS-7: the KILL enforcer refuses to kill a critical process (init/systemd/sshd/the DB/the fleet's
// own binaries), identified by its comm — a HIPS verdict must never take down the host or the
// platform itself. A non-critical process is killed.
func TestKillEnforcerRefusesCriticalProcesses(t *testing.T) {
	killed := -1
	names := map[int]string{
		10: "systemd", 11: "sshd", 12: "postgres", 13: "openshield-engi", // openshield* = the fleet
		20: "python3", // an ordinary process — killable
	}
	enf := process.NewKillEnforcerForTest(999,
		func(pid int) error { killed = pid; return nil },
		func(pid int) (string, error) { return names[pid], nil })

	dec := &corev1.Decision{Action: corev1.Action_ACTION_KILL_PROCESS}
	for _, pid := range []int{10, 11, 12, 13} {
		killed = -1
		if err := enf.EnforceTarget(context.Background(), dec, itoa(pid)); err == nil {
			t.Errorf("killed critical process %q (pid %d) — HIPS could take down the host/platform", names[pid], pid)
		}
		if killed != -1 {
			t.Errorf("the kill was actually invoked for critical pid %d", pid)
		}
	}
	// A non-critical process is killed.
	if err := enf.EnforceTarget(context.Background(), dec, "20"); err != nil {
		t.Fatalf("a non-critical process was refused: %v", err)
	}
	if killed != 20 {
		t.Errorf("the non-critical process was not killed (killed=%d)", killed)
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
