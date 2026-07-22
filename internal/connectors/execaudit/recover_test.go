package execaudit_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/connectors/execaudit"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// ENG-2: a panic in the per-record handling (a crafted record, or a panicking sink) is contained —
// the scan continues to the next record, never crashing the engine.
func TestExecScannerRecoversFromSinkPanic(t *testing.T) {
	stream := strings.Join([]string{
		`type=SYSCALL msg=audit(1.0:1): syscall=59 pid=1 exe="/bin/boom" key="exec"`,
		`type=EXECVE msg=audit(1.0:1): argc=1 a0="boom"`, // completing pair 1 → sink panics
		`type=SYSCALL msg=audit(1.0:2): syscall=59 pid=2 exe="/bin/ok" key="exec"`,
		`type=EXECVE msg=audit(1.0:2): argc=1 a0="ok"`, // pair 2 → must still be delivered
	}, "\n")
	delivered := 0
	sc := execaudit.NewScanner(func(ev *corev1.Event) {
		if ev.GetProcess().GetExecPath() == "/bin/boom" {
			panic("crafted record")
		}
		delivered++
	})
	if err := sc.Scan(context.Background(), strings.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	if delivered != 1 {
		t.Fatalf("delivered %d, want 1 (the scan must survive the panicking record and deliver the next)", delivered)
	}
	if sc.Dropped() < 1 {
		t.Error("the panicking record was not counted as dropped")
	}
}
