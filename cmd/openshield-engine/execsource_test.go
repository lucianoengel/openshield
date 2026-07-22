package main

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// HIPS-5c wiring: the exec source turns paired auditd records into a ProcessSubject Event on the
// engine's event channel — the connector→pipeline link for process executions.
func TestExecSourceFeedsProcessEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan *corev1.Event, 4)
	stream := strings.Join([]string{
		`type=SYSCALL msg=audit(1.0:7): syscall=59 ppid=1200 pid=4242 exe="/usr/bin/powershell" key="exec"`,
		`type=EXECVE msg=audit(1.0:7): argc=2 a0="powershell" a1="-enc"`,
	}, "\n")

	go func() { _ = execSource(ctx, strings.NewReader(stream), events, discardLogger()) }()

	select {
	case ev := <-events:
		if ev.GetKind() != corev1.EventKind_EVENT_KIND_PROCESS_EXEC {
			t.Errorf("kind = %v, want PROCESS_EXEC", ev.GetKind())
		}
		if ev.GetProcess().GetPid() != 4242 || ev.GetProcess().GetExecPath() != "/usr/bin/powershell" {
			t.Errorf("process = %+v, want pid 4242 /usr/bin/powershell", ev.GetProcess())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no process event produced from the auditd records — the exec source is not wired")
	}
}
