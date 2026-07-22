package process_test

import (
	"context"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/process"
)

// HIPS-7: the KILL target may carry the observation-time identity as "pid:start_ticks". The enforcer
// parses both and passes them to the kill, so the platform layer can revalidate against pid reuse. A
// bare pid yields start_ticks=0 (unknown → best-effort). A malformed target is an error, never a kill.
func TestEnforceTargetParsesStartTicks(t *testing.T) {
	var gotPid int
	var gotTicks uint64
	enf := process.NewKillEnforcerForTest(999,
		func(pid int, ticks uint64) error { gotPid, gotTicks = pid, ticks; return nil },
		func(int) (process.ProcIdentity, error) { return process.ProcIdentity{}, nil }) // never critical
	dec := &corev1.Decision{Action: corev1.Action_ACTION_KILL_PROCESS}

	if err := enf.EnforceTarget(context.Background(), dec, "42:12345"); err != nil {
		t.Fatalf("pid:ticks target rejected: %v", err)
	}
	if gotPid != 42 || gotTicks != 12345 {
		t.Errorf("parsed (%d, %d), want (42, 12345)", gotPid, gotTicks)
	}

	gotPid, gotTicks = -1, 999
	if err := enf.EnforceTarget(context.Background(), dec, "43"); err != nil {
		t.Fatalf("bare pid target rejected: %v", err)
	}
	if gotPid != 43 || gotTicks != 0 {
		t.Errorf("bare pid parsed (%d, %d), want (43, 0)", gotPid, gotTicks)
	}

	for _, bad := range []string{"abc", "42:xyz", "", ":5"} {
		if err := enf.EnforceTarget(context.Background(), dec, bad); err == nil {
			t.Errorf("malformed target %q did not error", bad)
		}
	}
}
