package execaudit_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/connectors/execaudit"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// TestScannerEmitsCapturedStartTicks (R34-5, test proposal #3, execaudit half): the
// exec source captures the process start-time at observation and the EMITTED event
// must carry it — this is the value the KILL enforcer revalidates to spare a
// recycled pid (HIPS-7). R34-5 found this plumbing had zero coverage: zeroing
// StartTicks at the source passed the whole suite green.
//
// The start-time reader is injected (the fabricated pid has no live /proc entry), so
// the test proves the captured value is threaded into the event, not that /proc is
// read. Mutation: dropping the `ps.StartTicks = s.startTicks(...)` line in Scan (or
// returning 0) makes the StartTicks assertion FAIL.
func TestScannerEmitsCapturedStartTicks(t *testing.T) {
	const wantTicks = 0xDEADBEEF
	var got []*corev1.Event
	sc := execaudit.NewScanner(func(ev *corev1.Event) { got = append(got, ev) })
	// Deterministic reader: this pid was observed with this exact start-time.
	execaudit.SetStartTicks(sc, func(pid int32) uint64 {
		if pid == 4242 {
			return wantTicks
		}
		return 0
	})

	stream := strings.Join([]string{
		`type=SYSCALL msg=audit(1626351234.123:456): syscall=59 ppid=1200 pid=4242 exe="/usr/bin/powershell" key="exec"`,
		`type=EXECVE msg=audit(1626351234.123:456): argc=1 a0="powershell"`,
	}, "\n")
	if err := sc.Scan(context.Background(), strings.NewReader(stream)); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("emitted %d events, want 1", len(got))
	}
	ps := got[0].GetProcess()
	if ps == nil {
		t.Fatal("emitted event has no process subject")
	}
	if ps.GetStartTicks() != wantTicks {
		t.Fatalf("emitted StartTicks = %#x, want %#x — the observation-time start-time was not captured onto the event (HIPS-7 pid-reuse defense inert)", ps.GetStartTicks(), wantTicks)
	}
}
