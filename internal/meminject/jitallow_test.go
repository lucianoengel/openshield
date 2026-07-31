package meminject

import (
	"strings"
	"testing"
)

func allowlist(t *testing.T, body string) JITAllowlist {
	t.Helper()
	a, err := ParseJITAllowlist(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parsing the allowlist: %v", err)
	}
	return a
}

// anon and backed build the two region shapes the allowlist distinguishes.
func anon() Region { return Region{Start: 0x1000, End: 0x2000, Perms: "rwxp"} }
func backed(p string) Region {
	return Region{Start: 0x3000, End: 0x4000, Perms: "rwxp", Path: p}
}

// THE ALLOWLIST EXISTS SO THE DETECTOR STAYS ON.
//
// Every JIT on the machine writes instructions into memory and executes them, which by permission bits
// alone is what shellcode does. Without an exemption the scanner reports the browser on every scan, the
// operator stops reading it, and a detector nobody reads is not a detector.
func TestAnAllowlistedJITsAnonymousRegionsAreExplained(t *testing.T) {
	a := allowlist(t, "/usr/lib/firefox/firefox\n")
	if got := a.Unexplained("/usr/lib/firefox/firefox", []Region{anon(), anon()}); len(got) != 0 {
		t.Fatalf("%d regions still unexplained for an allowlisted JIT — the scanner would alert on every "+
			"browser on the machine, and an alert that fires constantly is one nobody reads", len(got))
	}
}

// A PROCESS THAT IS NOT ON THE LIST IS NOT EXEMPT — the detector, doing its job.
func TestAnUnlistedProcessIsStillReported(t *testing.T) {
	a := allowlist(t, "/usr/lib/firefox/firefox\n")
	if got := a.Unexplained("/tmp/payload", []Region{anon()}); len(got) != 1 {
		t.Fatalf("an unlisted process's W+X memory was explained away (%d unexplained, want 1)", len(got))
	}
}

// FILE-BACKED W+X SURVIVES THE EXEMPTION, and this is the property that keeps the allowlist from being
// a hole.
//
// A JIT allocates ANONYMOUS memory and writes code into it. Nothing legitimate maps a FILE writable and
// executable. Browsers are also the most-targeted injection host on the machine, so an exemption that
// covered every W+X region in an allowlisted process would put a permanent blind spot exactly where an
// attacker most wants one — and the alert the operator stopped seeing would be the one that mattered.
//
// Mutation (suppress every region for an allowlisted exe, not just anonymous ones): FAIL, verified.
func TestAFileBackedWXRegionIsReportedEvenForAnAllowlistedJIT(t *testing.T) {
	a := allowlist(t, "/usr/lib/firefox/firefox\n")
	got := a.Unexplained("/usr/lib/firefox/firefox", []Region{anon(), backed("/tmp/evil.so"), anon()})
	if len(got) != 1 {
		t.Fatalf("%d regions unexplained, want exactly the file-backed one. An allowlist that covers "+
			"every W+X region in a browser is a permanent blind spot in the most-targeted process on "+
			"the machine", len(got))
	}
	if got[0].Path != "/tmp/evil.so" {
		t.Fatalf("the surviving region is %q, want the file-backed mapping", got[0].Path)
	}
}

// A DELETED EXECUTABLE IS NEVER VOUCHED FOR.
//
// The kernel appends "(deleted)" to /proc/<pid>/exe when a running process's binary has been unlinked,
// which is exactly the shape of run-then-replace: start something allowlisted, delete it, and the path
// keeps speaking for a file nobody can inspect any more. The exemption is granted to a file on disk, so
// when the file is gone the exemption goes with it.
//
// Mutation (match on the path with the suffix stripped): the deleted process is exempted → FAIL.
func TestADeletedExecutableLosesItsExemption(t *testing.T) {
	a := allowlist(t, "/usr/lib/firefox/firefox\n")
	got := a.Unexplained("/usr/lib/firefox/firefox (deleted)", []Region{anon()})
	if len(got) != 1 {
		t.Fatal("a process whose executable had been DELETED kept its allowlist exemption. That is the " +
			"run-then-replace shape: the path vouches for a file that no longer exists and cannot be " +
			"checked, so an attacker inherits the exemption by unlinking the binary")
	}
}

// AN UNIDENTIFIABLE PROCESS IS NOT PERMITTED.
//
// An empty exe path means the scan could not read it — a different user's process without privilege, or
// one that exited mid-scan. "Could not tell" must never resolve to "permitted" (D31): that would exempt
// precisely the processes the scanner has least visibility into.
func TestAProcessWhoseExecutableCouldNotBeReadIsNotExempt(t *testing.T) {
	a := allowlist(t, "/usr/lib/firefox/firefox\n")
	if got := a.Unexplained("", []Region{anon()}); len(got) != 1 {
		t.Fatal("a process whose executable path could not be read was treated as allowlisted — 'could " +
			"not tell' became 'permitted', which exempts exactly the processes least visible to the scan")
	}
}

// A NAMED ANONYMOUS MAPPING IS STILL ANONYMOUS, and this is the case a real machine taught.
//
// Since Linux 5.17 a process can name its anonymous mappings, and V8 does: a Node or Chrome JIT region
// appears in /proc/<pid>/maps as `[anon:JSJITCode]`. Treating any non-empty pathname as a file — which
// the first version of this did — means the exemption silently fails on the most common JIT on the
// machine, and the operator sees their browser reported despite having listed it.
//
// Mutation (test non-emptiness instead of absoluteness): the V8 region is reported → FAIL, verified.
func TestAKernelNamedAnonymousRegionIsNotMistakenForAFile(t *testing.T) {
	a := allowlist(t, "/usr/bin/node\n")
	for _, name := range []string{"[anon:JSJITCode]", "[heap]", "[stack]"} {
		if got := a.Unexplained("/usr/bin/node", []Region{backed(name)}); len(got) != 0 {
			t.Errorf("%s was treated as a file-backed mapping. It is anonymous memory with a label on "+
				"it, and reading it as a file means an allowlisted JIT is reported anyway", name)
		}
	}
}

// A RUNTIME MAY BE GRANTED THE FILES IT REALLY DOES MAP W+X — no more.
//
// Measured on a real machine: a JVM with class-data sharing maps `classes.jsa` rwxp straight from disk.
// An absolute "file-backed is always suspicious" rule reports every JVM forever, which is the noise this
// allowlist exists to prevent. So an entry may name the directories that executable is permitted to map
// from, and an attacker's mapping outside them still alerts.
func TestAGrantedMappingDirectoryExplainsARealRuntimesFileBackedRegion(t *testing.T) {
	a := allowlist(t, "/usr/lib/jvm/java-11/bin/java /usr/lib/jvm/\n")
	const java = "/usr/lib/jvm/java-11/bin/java"

	if got := a.Unexplained(java, []Region{backed("/usr/lib/jvm/java-11/lib/server/classes.jsa")}); len(got) != 0 {
		t.Fatalf("the JVM's class-data-sharing archive was reported (%d unexplained) even though its "+
			"directory was granted — every JVM on the fleet would alert forever", len(got))
	}
	// The grant is a DIRECTORY, so a sibling path that merely shares a prefix does not inherit it.
	if got := a.Unexplained(java, []Region{backed("/usr/lib/jvm-evil/payload.so")}); len(got) != 1 {
		t.Fatal("a path that merely shares a string prefix with the granted directory inherited the " +
			"grant — /usr/lib/jvm must not vouch for /usr/lib/jvm-evil")
	}
	if got := a.Unexplained(java, []Region{backed("/tmp/evil.so")}); len(got) != 1 {
		t.Fatal("a mapping outside every granted directory was explained away — the grant has become a " +
			"blanket exemption, which is exactly what it exists to avoid")
	}
}

// A GRANT OF "/" IS REFUSED, because it is not a bound.
func TestAGrantOfTheWholeFilesystemIsRefused(t *testing.T) {
	if _, err := ParseJITAllowlist(strings.NewReader("/usr/bin/java /\n")); err == nil {
		t.Fatal("an entry granting the whole filesystem was accepted — that executable could then map " +
			"ANY file writable and executable, which is the entire exposure this list bounds")
	}
	if _, err := ParseJITAllowlist(strings.NewReader("/usr/bin/java lib/\n")); err == nil {
		t.Fatal("a relative mapping prefix was accepted; a maps pathname is always absolute, so it " +
			"could never match")
	}
}

// AN EMPTY ALLOWLIST EXEMPTS NOTHING, so an unconfigured scanner is loud rather than blind.
func TestTheZeroAllowlistPermitsNothing(t *testing.T) {
	var a JITAllowlist
	if got := a.Unexplained("/usr/lib/firefox/firefox", []Region{anon()}); len(got) != 1 {
		t.Fatal("the zero-value allowlist exempted a process. An unconfigured scanner must report every " +
			"suspect, never silently exempt a set it inferred")
	}
	if a.Len() != 0 {
		t.Fatalf("Len = %d for the zero value", a.Len())
	}
}

// ENTRIES THAT COULD NEVER MATCH ARE REFUSED AT LOAD, not accepted and quietly ignored.
//
// /proc/<pid>/exe is always an absolute path, so a relative entry matches nothing. Accepting it would
// leave a line in the operator's file that looks like an exemption and is none — discovered, if ever, as
// an alert they believed was suppressed.
func TestAnEntryThatCouldNeverMatchIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"relative", "usr/lib/firefox/firefox\n"},
		{"bare name", "firefox\n"},
		{"deleted", "/usr/lib/firefox/firefox (deleted)\n"},
	} {
		if _, err := ParseJITAllowlist(strings.NewReader(tc.body)); err == nil {
			t.Errorf("%s: an entry that can never match was accepted, so it sits in the file looking "+
				"like an exemption while exempting nothing", tc.name)
		}
	}
}

// COMMENTS AND BLANK LINES ARE ORDINARY, because an operator maintaining this list needs to say WHY a
// path is on it — and a list nobody can annotate is one nobody prunes.
func TestTheListCanBeAnnotated(t *testing.T) {
	a := allowlist(t, "# the browser's JIT\n\n/usr/lib/firefox/firefox\n\n#/usr/bin/old-runtime\n")
	if a.Len() != 1 {
		t.Fatalf("Len = %d, want 1 — comments and blanks must not become entries, and a commented-out "+
			"path must not stay in force", a.Len())
	}
	if got := a.Unexplained("/usr/bin/old-runtime", []Region{anon()}); len(got) != 1 {
		t.Fatal("a COMMENTED-OUT path kept its exemption — an operator who disables an entry has not " +
			"disabled anything")
	}
}
