package execaudit_test

import (
	"testing"

	"github.com/lucianoengel/openshield/internal/behavioral"
	"github.com/lucianoengel/openshield/internal/connectors/execaudit"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Real auditd records for a suspicious exec (powershell -enc).
const (
	syscallLine = `type=SYSCALL msg=audit(1626351234.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1200 pid=4242 uid=1000 comm="powershell" exe="/usr/bin/powershell" key="exec"`
	execveLine  = `type=EXECVE msg=audit(1626351234.123:456): argc=3 a0="powershell" a1="-enc" a2="SQBFAFgA"`
)

func TestParseAndCombine(t *testing.T) {
	s, err := execaudit.ParseSyscall(syscallLine)
	if err != nil {
		t.Fatal(err)
	}
	if s.PID != 4242 || s.PPID != 1200 {
		t.Errorf("pid/ppid = %d/%d, want 4242/1200 (note: pid must not match ppid)", s.PID, s.PPID)
	}
	if s.Exe != "/usr/bin/powershell" {
		t.Errorf("exe = %q", s.Exe)
	}

	e, err := execaudit.ParseExecve(execveLine)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Args) != 3 || e.Args[0] != "powershell" || e.Args[1] != "-enc" {
		t.Errorf("args = %v, want [powershell -enc SQBFAFgA]", e.Args)
	}

	ev, err := execaudit.ToEvent(s, e)
	if err != nil {
		t.Fatal(err)
	}
	if ev.GetKind() != corev1.EventKind_EVENT_KIND_PROCESS_EXEC {
		t.Errorf("kind = %v", ev.GetKind())
	}
	p := ev.GetProcess()
	if p.GetPid() != 4242 || p.GetExecPath() != "/usr/bin/powershell" || len(p.GetArgs()) != 3 {
		t.Errorf("process subject = %+v", p)
	}

	// The full HIPS producer→detector path: the produced Event's exec fields feed the
	// behavioral analyzer (D110), which flags the encoded PowerShell.
	f := behavioral.Analyze(p.GetExecPath(), p.GetParentPath(), p.GetArgs())
	if f.LOLBin == "" || !f.EncodedCommand {
		t.Errorf("behavioral analyzer did not flag the produced exec event: %+v", f)
	}
}

// The pid/ppid field extraction must not confuse "pid" with "ppid" (whole-token match).
func TestFieldWholeToken(t *testing.T) {
	s, err := execaudit.ParseSyscall(`type=SYSCALL msg=audit(1.1:1): ppid=1200 pid=4242 exe="/bin/sh"`)
	if err != nil {
		t.Fatal(err)
	}
	if s.PID != 4242 {
		t.Errorf("pid = %d, want 4242 (ppid must not shadow pid)", s.PID)
	}
	if s.PPID != 1200 {
		t.Errorf("ppid = %d, want 1200", s.PPID)
	}
}

func TestRejectsMalformedOrMismatched(t *testing.T) {
	// SYSCALL with no exe.
	if _, err := execaudit.ParseSyscall(`type=SYSCALL msg=audit(1.1:1): pid=1`); err == nil {
		t.Error("SYSCALL with no exe parsed")
	}
	// No audit id.
	if _, err := execaudit.ParseSyscall(`type=SYSCALL pid=1 exe="/bin/sh"`); err == nil {
		t.Error("record with no audit() id parsed")
	}
	// Mismatched pair (different audit ids) must not stitch.
	s, _ := execaudit.ParseSyscall(syscallLine)
	e, _ := execaudit.ParseExecve(`type=EXECVE msg=audit(9999.9:9): argc=1 a0="x"`)
	if _, err := execaudit.ToEvent(s, e); err == nil {
		t.Error("ToEvent stitched two records with different audit ids")
	}
}
