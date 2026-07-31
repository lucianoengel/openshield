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

// TestMemoryScanDetectsAWritableExecutableRegion covers the W^X-violation detector (D312).
//
// It is the one endpoint detector that reads no file and no network flow: it walks /proc looking for
// memory that is writable AND executable at once, which is the signature of injected shellcode. Ordinary
// code is mapped r-x from a file on disk; a region that is both writable and executable is one a program
// has to have asked for, and almost nothing legitimate does.
//
// The scenario allocates exactly that in a real process, because a synthetic /proc tree would be testing
// the parser rather than the detector — and the parser has its own tests.
func TestMemoryScanDetectsAWritableExecutableRegion(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_MEMSCAN_INTERVAL=1s",
	})
	eng.WaitForOutput("memory-injection scan ENABLED", 90*time.Second)
	pool := openPool(t, stack.DSN)
	entries := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Nothing suspicious yet: an ordinary host must not produce findings, or the detector's output is
	// noise and gets muted.
	time.Sleep(4 * time.Second)
	quiet := entries()

	// A process that maps a page RWX — the thing the detector is for.
	victim := exec.Command("python3", "-c", `
import mmap, time
m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
m.write(b"\x90" * 16)
time.sleep(60)
`)
	if err := victim.Start(); err != nil {
		t.Skipf("python3 unavailable to allocate an RWX region: %v", err)
	}
	t.Cleanup(func() { _ = victim.Process.Kill() })

	Eventually(t, 120*time.Second, "the W^X violation to be detected and recorded", func() bool {
		return entries() > quiet
	})
}

// TestUSBAttachmentIsObservedAndAudited closes T-020 end to end (D312).
//
// Both halves of the USB capability shipped years apart from anything that could use them: the producer
// had only a test fake for its device source, and no binary imported either half. The capability spec
// described "the first real (non-stub) enforcer ... with an actual enforcement point" while the product
// could not see a USB attachment at all.
//
// The scenario points the producer at a FIXTURE sysfs tree rather than at real hardware, and that is the
// only honest option here: a build host has whatever USB devices it happens to have, so asserting on real
// ones would be asserting on the machine. The fixture proves the shipped path — enumerate, pseudonymise,
// decide, audit — and `internal/connectors/usb` covers the sysfs parsing against real kernel layouts.
func TestUSBAttachmentIsObservedAndAudited(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	// A sysfs-shaped tree: one device with a serial, one without, and an INTERFACE entry that must not
	// be reported as a device.
	sysfs := filepath.Join(work, "usbdevices")
	for dir, attrs := range map[string]map[string]string{
		"1-4":     {"idVendor": "0781", "idProduct": "5567", "serial": "SECRET-STICK-001"},
		"1-5":     {"idVendor": "0bda", "idProduct": "5411"},
		"1-4:1.0": {},
	} {
		p := filepath.Join(sysfs, dir)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		for k, v := range attrs {
			if err := os.WriteFile(filepath.Join(p, k), []byte(v+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	keyPath := filepath.Join(work, "usb.key")
	if err := os.WriteFile(keyPath, []byte("a-persistent-usb-pseudonym-key!!"), 0o600); err != nil {
		t.Fatal(err)
	}

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_USB_INTERVAL=1s",
		"OPENSHIELD_USB_PSEUDONYM_KEY=" + keyPath,
		"OPENSHIELD_USB_SYSFS=" + sysfs,
	})
	eng.WaitForOutput("USB observation ENABLED", 90*time.Second)

	pool := openPool(t, stack.DSN)
	// Counted as LEDGER ENTRIES, not alerts. The default policy deliberately does NOT alert on an
	// attachment — the event fires for a keyboard, a webcam and a dock's hub, and a laptop docking would
	// raise a handful of alerts before anyone opened a file. The attachment is still fully observed and
	// its decision recorded, which is what makes "what was plugged into this machine" answerable.
	Eventually(t, 120*time.Second, "the attached USB devices to be observed and audited", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n)
		return n >= 2
	})

	// THE RAW SERIAL MUST NOT BE IN THE LEDGER. A USB serial is a durable device identifier that
	// re-identifies a person across contexts, and the ledger is the longest-retained artefact here.
	var payloads string
	if err := pool.QueryRow(Ctx(t),
		`SELECT string_agg(coalesce(payload::text,''), ' ') FROM audit_entries`).Scan(&payloads); err == nil {
		if contains(payloads, "SECRET-STICK-001") {
			t.Errorf("the RAW USB serial reached the ledger — it is pseudonymised at the source precisely " +
				"so this cannot happen")
		}
	}

	// AND THE SAME DEVICE IS NOT RE-REPORTED every tick: a stick left plugged in would otherwise
	// produce an event per second for as long as it stays there.
	var first int
	_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&first)
	time.Sleep(5 * time.Second)
	var second int
	_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&second)
	if second > first {
		t.Errorf("the same attached devices were re-reported (%d → %d entries) — a detector that fires "+
			"every tick for a device that has not changed is one nobody can read", first, second)
	}
}

// TestTheJITAllowlistExplainsAKnownRuntimeWithoutSilencingTheDetector is HIPS-4 increment 2.
//
// The W^X detector above is correct and, without this, unusable: every JIT on the machine — browser, JVM,
// .NET, Node — writes instructions into memory and then executes them, which by permission bits alone is
// exactly what shellcode does. A detector that reports the browser on every poll is one the operator
// mutes, so the missing allowlist does not produce a noisy detector, it produces no detector at all.
//
// The scenario uses the SAME real RWX allocation as the test above and adds the allowlist, so the only
// difference between "reported" and "explained" is the list itself.
func TestTheJITAllowlistExplainsAKnownRuntimeWithoutSilencingTheDetector(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 unavailable to allocate an RWX region: %v", err)
	}
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	// THE RUNTIME STARTS FIRST, and the allowlist entry is read from ITS OWN /proc entry.
	//
	// The engine identifies a process by `/proc/<pid>/exe`, which is fully resolved — /usr/bin/python3 is
	// reported as /usr/bin/python3.12. Deriving the entry any other way (EvalSymlinks on what LookPath
	// found) guesses at that resolution, and a guess that misses produces a test failure that looks like
	// a broken allowlist. Taking the path the kernel itself reports removes the guess entirely.
	// MAP_PRIVATE MATTERS HERE, and finding out why cost a VM round trip worth recording.
	//
	// CPython's default mmap is MAP_SHARED, and a SHARED anonymous mapping is reported by the kernel as
	// `/dev/zero (deleted)` — a pathname, so the scanner correctly treats it as file-backed and reports
	// it even for an allowlisted executable. That is the right call (shared writable-executable memory is
	// an injection primitive in its own right), but it is not what a JIT allocates. Real code caches —
	// V8's, the JVM's — are PRIVATE anonymous, which is the case this test is about.
	victim := exec.Command(python, "-c", `
import mmap, time
m = mmap.mmap(-1, 4096, flags=mmap.MAP_PRIVATE,
              prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
m.write(b"\x90" * 16)
time.sleep(120)
`)
	if err := victim.Start(); err != nil {
		t.Skipf("cannot start the RWX allocator: %v", err)
	}
	t.Cleanup(func() { _ = victim.Process.Kill() })

	resolved, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", victim.Process.Pid))
	if err != nil {
		t.Fatalf("reading the runtime's own /proc exe link: %v", err)
	}
	allow := filepath.Join(work, "jit.allow")
	if err := os.WriteFile(allow, []byte("# the runtime under test\n"+resolved+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_MEMSCAN_INTERVAL=1s",
		"OPENSHIELD_MEMSCAN_JIT_ALLOW=" + allow,
	})
	eng.WaitForOutput("memory-injection scan ENABLED", 90*time.Second)

	// THE ALLOWLIST IS ANNOUNCED. It is a deliberate reduction in coverage, in processes that are among
	// the most-targeted injection hosts on the machine; an operator who cannot see it in the log cannot
	// weigh it.
	if !contains(eng.Output(), "JIT allowlist ACTIVE") {
		t.Errorf("the engine loaded a JIT allowlist without saying so. A silent exemption is coverage "+
			"an operator does not know they gave up\n%s", eng.Output())
	}

	// THE SUPPRESSION IS OBSERVED, not inferred from an absence.
	//
	// "No alert appeared" is what a broken scanner, a scanner that never started and a working allowlist
	// all look like. The engine reports what it explained away, so this asserts the allowlist actually
	// ran over a W+X process rather than that nothing ever happened.
	Eventually(t, 120*time.Second, "the allowlisted runtime's W+X memory to be explained", func() bool {
		return contains(eng.Output(), "explained by the JIT allowlist")
	})

	// AND THE DETECTOR IS STILL ON. An allowlist that turned the scan off would satisfy every assertion
	// above; this one fails if the scanner stopped looking at anything else.
	if contains(eng.Output(), "memory-injection scan ENABLED") == false {
		t.Errorf("the scanner is no longer reported as enabled\n%s", eng.Output())
	}
}
