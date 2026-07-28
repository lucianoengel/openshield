//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// THE AUDITD EXEC SOURCE END TO END (HIPS-5c, OPENSHIELD_EXEC_AUDIT_LOG).
//
// `internal/connectors/execaudit` measured at ZERO integration coverage, and driving it found that the
// engine drained the configured file once and stopped: the scanner's loop ends at EOF and returns nil,
// so every execution recorded BEFORE startup was ingested, none after it, and nothing said so. The
// startup line read "exec connector ENABLED" either way.
//
// THE RECORDS ARE THEREFORE APPENDED AFTER THE ENGINE IS RUNNING. Writing them first would pass against
// the old behaviour, which is precisely how the defect survived having a fully unit-tested parser.

// auditRecords renders the SYSCALL+EXECVE pair auditd emits for one execution. Both are required: the
// connector pairs them by audit id, and either alone is an incomplete record it drops.
func auditRecords(auditID, exe string, args ...string) string {
	syscall := fmt.Sprintf(
		`type=SYSCALL msg=audit(%s): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=4242 `+
			`auid=1000 uid=1000 gid=1000 comm="sh" exe="%s" key="exec"`, auditID, exe)
	execve := fmt.Sprintf(`type=EXECVE msg=audit(%s): argc=%d`, auditID, len(args))
	for i, a := range args {
		execve += fmt.Sprintf(" a%d=\"%s\"", i, a)
	}
	return syscall + "\n" + execve + "\n"
}

// TestAnExecRecordAppendedAfterStartupIsIngested.
//
// The assertion is on the AUDIT ROW. "The connector is enabled" is a startup line, and this project has
// had four of those be true while nothing downstream happened.
func TestAnExecRecordAppendedAfterStartupIsIngested(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	auditLog := filepath.Join(work, "audit.log")

	// The file exists and is EMPTY at startup: the engine reaches EOF immediately, which is the exact
	// state in which the old code gave up.
	if err := os.WriteFile(auditLog, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_EXEC_AUDIT_LOG=" + auditLog,
	})
	eng.WaitForOutput("exec connector ENABLED", 90*time.Second)

	// THE MODE IS ON THE STARTUP LINE. "following" and "read-once" behave completely differently, and
	// an operator has to be able to tell which one they configured before an incident, not during one.
	if !contains(eng.Output(), "following") {
		t.Errorf("the exec connector did not report that it is FOLLOWING a regular file. Read-once "+
			"against an audit log ingests the backlog and then sees nothing, forever:\n%s", eng.Output())
	}

	pool := openPool(t, stack.DSN)
	entries := func() int {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n)
		return n
	}
	before := entries()

	// APPENDED NOW — after the engine has already reached the end of the file.
	appended := auditRecords("1700000000.111:4242", "/usr/bin/curl", "curl", "-sL", "https://example.test")
	af, err := os.OpenFile(auditLog, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := af.WriteString(appended); err != nil {
		t.Fatal(err)
	}
	af.Close()

	Eventually(t, 90*time.Second, "the execution appended AFTER startup to reach the ledger", func() bool {
		return entries() > before
	})

	// AND IT IS A PROCESS EVENT, not something else that happened to land in the ledger. Without this
	// the count could rise from any unrelated source and the scenario would pass having proved nothing
	// about the exec connector.
	var eventID string
	if err := pool.QueryRow(Ctx(t),
		`SELECT event_id FROM audit_entries ORDER BY sequence DESC LIMIT 1`).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	if !contains(eventID, "exec") && !contains(eng.Output(), "/usr/bin/curl") {
		t.Errorf("the newest ledger entry (%q) does not look like the appended execution, and the "+
			"engine never mentions the executable — the count may have risen from something else\n%s",
			eventID, eng.Output())
	}

	// A SECOND record, to show the source keeps producing rather than delivering once and stalling.
	baseline := entries()
	af2, err := os.OpenFile(auditLog, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := af2.WriteString(
		auditRecords("1700000000.222:4243", "/bin/sh", "sh", "-c", "id")); err != nil {
		t.Fatal(err)
	}
	af2.Close()
	Eventually(t, 90*time.Second, "a SECOND appended execution to be ingested", func() bool {
		return entries() > baseline
	})
}

// TestTheExecSourceEndingIsAnnounced.
//
// A source that ends under a running engine is a loss of endpoint process visibility, and the operator
// cannot tell it from a quiet estate. A fifo whose writer closes is the realistic way this happens —
// the documented deployment shape is a `tail -F` piped into one, and that pipeline can die.
func TestTheExecSourceEndingIsAnnounced(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	fifo := filepath.Join(work, "audit.fifo")

	if err := mkfifo(fifo); err != nil {
		t.Skipf("cannot create a fifo here: %v", err)
	}

	// A writer must exist before the engine opens the fifo, or the open blocks.
	w, err := os.OpenFile(fifo, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_EXEC_AUDIT_LOG=" + fifo,
	})
	eng.WaitForOutput("exec connector ENABLED", 90*time.Second)

	// A fifo is NOT followed — it blocks correctly while a writer holds it open, so wrapping it would
	// add a poll to a path that is already right.
	if !contains(eng.Output(), "read-once") {
		t.Errorf("a fifo was reported as %q; it should not be wrapped in the file follower:\n%s",
			"following", eng.Output())
	}

	// Close the writer: the fifo returns EOF, which is a real end of source.
	w.Close()
	eng.WaitForOutput("exec source ENDED", 60*time.Second)
	if !contains(eng.Output(), "no further process executions") {
		t.Errorf("the end-of-source warning does not say what was lost, so it reads as routine:\n%s",
			eng.Output())
	}
}

// mkfifo creates a named pipe via the shell tool rather than a syscall, so this file needs no
// build-tagged variant — the integration suite compiles on macOS in CI, where the syscall package
// spells it differently.
func mkfifo(path string) error { return exec.Command("mkfifo", path).Run() }
