package execaudit_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/lucianoengel/openshield/internal/connectors/execaudit"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// HIPS-5c: the exec source pairs auditd SYSCALL+EXECVE records by audit id into ProcessSubject
// Events, drops an unpairable/malformed record (counted), and interleaving pairs are matched by id
// — the built parsers become a running producer feeding the pipeline.
func TestExecScannerPairsRecords(t *testing.T) {
	stream := strings.Join([]string{
		// pair A (id 456): a powershell exec with an encoded command
		`type=SYSCALL msg=audit(1626351234.123:456): syscall=59 ppid=1200 pid=4242 exe="/usr/bin/powershell" key="exec"`,
		`type=EXECVE msg=audit(1626351234.123:456): argc=3 a0="powershell" a1="-enc" a2="SQBFAFgA"`,
		// a malformed SYSCALL (no exe) — dropped
		`type=SYSCALL msg=audit(1626351234.200:457): syscall=59 pid=99`,
		// pair B (id 458), records interleaved with pair C's SYSCALL
		`type=SYSCALL msg=audit(1626351234.300:458): syscall=59 ppid=1 pid=555 exe="/bin/bash" key="exec"`,
		`type=SYSCALL msg=audit(1626351234.400:459): syscall=59 ppid=2 pid=666 exe="/bin/sh" key="exec"`,
		`type=EXECVE msg=audit(1626351234.300:458): argc=1 a0="bash"`,
		`type=EXECVE msg=audit(1626351234.400:459): argc=1 a0="sh"`,
	}, "\n")

	var mu sync.Mutex
	var got []*corev1.Event
	sc := execaudit.NewScanner(func(ev *corev1.Event) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})
	if err := sc.Scan(context.Background(), strings.NewReader(stream)); err != nil {
		t.Fatal(err)
	}

	if len(got) != 3 {
		t.Fatalf("emitted %d events, want 3 (pairs A/B/C; the exe-less SYSCALL dropped)", len(got))
	}
	byPid := map[int32]*corev1.Event{}
	for _, ev := range got {
		byPid[ev.GetProcess().GetPid()] = ev
	}
	if a := byPid[4242]; a == nil || a.GetProcess().GetExecPath() != "/usr/bin/powershell" || len(a.GetProcess().GetArgs()) != 3 {
		t.Errorf("pair A mis-assembled: %+v", a.GetProcess())
	}
	if b := byPid[555]; b == nil || b.GetProcess().GetExecPath() != "/bin/bash" {
		t.Errorf("pair B (interleaved) not matched by id: %+v", b)
	}
	if c := byPid[666]; c == nil || c.GetProcess().GetExecPath() != "/bin/sh" {
		t.Errorf("pair C (interleaved) not matched by id: %+v", c)
	}
	if sc.Dropped() < 1 {
		t.Errorf("dropped = %d, want >= 1 (the exe-less SYSCALL)", sc.Dropped())
	}
}

// The pending-pair buffer is bounded: a flood of unpaired SYSCALL records (no EXECVE ever) does not
// grow without limit — the oldest are evicted and counted, and no event is wrongly emitted.
func TestExecScannerBoundsUnpairedFlood(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20000; i++ {
		b.WriteString(`type=SYSCALL msg=audit(1.0:`)
		b.WriteString(itoa(i))
		b.WriteString(`): syscall=59 pid=1 exe="/bin/x" key="exec"` + "\n")
	}
	emitted := 0
	sc := execaudit.NewScanner(func(*corev1.Event) { emitted++ })
	if err := sc.Scan(context.Background(), strings.NewReader(b.String())); err != nil {
		t.Fatal(err)
	}
	if emitted != 0 {
		t.Errorf("emitted %d events from unpaired SYSCALLs, want 0", emitted)
	}
	if sc.Dropped() == 0 {
		t.Error("a flood of unpaired records was not evicted/counted (possible unbounded buffer)")
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
