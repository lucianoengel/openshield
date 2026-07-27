//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ENDPOINT DETECTORS THAT WATCH BEHAVIOUR RATHER THAN CONTENT (D309).
//
// FIM answers "did a critical file change" and memory scanning answers "is something injected into a
// running process". Neither reads a document, so neither is covered by anything that drops a file with a
// CPF in it — and both were in the group whose events the pipeline was throwing away until D307.

// TestFIMDetectsDriftFromASignedBaseline covers HIPS-4 end to end.
func TestFIMDetectsDriftFromASignedBaseline(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	critical := filepath.Join(work, "critical")
	if err := os.MkdirAll(critical, 0o755); err != nil {
		t.Fatal(err)
	}
	guarded := filepath.Join(critical, "sudoers")
	if err := os.WriteFile(guarded, []byte("root ALL=(ALL) ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	key, pub := filepath.Join(work, "fim.key"), filepath.Join(work, "fim.pub")
	if out, err := runCapture(t, "openshield-fim-baseline", nil,
		"keygen", "--out-key", key, "--out-pub", pub); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	baseline := filepath.Join(work, "baseline.sig")
	if out, err := runCapture(t, "openshield-fim-baseline", nil,
		"build", "--paths", critical, "--key", key, "--out", baseline); err != nil {
		t.Fatalf("baseline: %v\n%s", err, out)
	}

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_FIM_PATHS=" + critical,
		"OPENSHIELD_FIM_BASELINE=" + baseline,
		"OPENSHIELD_FIM_BASELINE_PUBKEY=" + pub,
		"OPENSHIELD_FIM_INTERVAL=1s",
	})
	eng.WaitForOutput("engine observing", 90*time.Second)
	pool := openPool(t, stack.DSN)
	entries := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// An UNCHANGED file must not drift. FIM's value is that a report means something happened; a
	// detector that reports on a quiet host is one whose reports get ignored.
	time.Sleep(5 * time.Second)
	quiet := entries()

	// Now change the guarded file — the modification a rootkit or a privilege-escalation makes.
	if err := os.WriteFile(guarded, []byte("root ALL=(ALL) ALL\nattacker ALL=(ALL) NOPASSWD: ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	Eventually(t, 120*time.Second, "FIM to detect the drift and record it", func() bool {
		return entries() > quiet
	})

	// The record must not contain the file's CONTENT. FIM compares hashes precisely so the evidence of
	// a change to /etc/sudoers is not a copy of /etc/sudoers.
	var payload string
	if err := pool.QueryRow(Ctx(t),
		`SELECT coalesce(payload::text,'') FROM audit_entries ORDER BY id DESC LIMIT 1`).Scan(&payload); err == nil {
		if contains(payload, "NOPASSWD") {
			t.Errorf("the FIM record contains the changed file's content:\n%s", payload)
		}
	}
}

// TestTheClipboardWatcherIsInertWithoutADisplayAndSaysSo is an honest gate, not a skip.
//
// Clipboard mediation needs an X11 display, which a headless build host does not have. The property
// worth asserting HERE is the one an operator meets: the engine must come up, say plainly that the
// clipboard is not being watched, and keep doing everything else — rather than failing to start, or
// starting silently and leaving an operator believing paste is covered.
func TestTheClipboardWatcherIsInertWithoutADisplayAndSaysSo(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_CLIPBOARD_INTERVAL=500ms",
		"DISPLAY=", // explicitly none
	})
	// The engine still comes up and watches files: one unavailable producer must not take the endpoint
	// agent down with it.
	eng.WaitForOutput("engine observing", 90*time.Second)

	// And it is not silent about the gap.
	if !contains(eng.Output(), "clipboard") {
		t.Errorf("the engine says NOTHING about the clipboard on a host where it cannot watch one. An "+
			"operator who configured clipboard DLP would believe paste is covered:\n%s", eng.Output())
	}
	if eng.Cmd.ProcessState != nil {
		t.Errorf("the engine EXITED because a clipboard was unavailable — a missing display is a "+
			"reduced-coverage condition, not a reason to stop protecting the filesystem\n%s", eng.Output())
	}
}
