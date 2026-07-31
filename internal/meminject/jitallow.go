package meminject

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// THE JIT ALLOWLIST (HIPS-4 increment 2).
//
// W+X memory is the injected-code signature, and it is also how every just-in-time compiler on the
// machine does its job. A browser, a JVM, a .NET runtime and a Node process all write instructions into
// memory and then execute them, which is the same thing shellcode does and is indistinguishable from it
// by permission bits alone. A scanner without an allowlist therefore reports the browser every time it
// runs, and the operator turns the scanner off — so the missing allowlist does not produce a noisy
// detector, it produces no detector at all.
//
// THE DANGER IS THE OPPOSITE ONE, AND IT SHAPES EVERYTHING HERE. Browsers are the most-targeted
// injection host on the machine. An allowlist that said "this process may have W+X memory" would put a
// permanent hole exactly where an attacker most wants one, and the alert an operator stopped seeing is
// the one they most needed. So this suppresses as little as it can:
//
//   - ONLY ANONYMOUS regions, by default. A JIT allocates anonymous memory and writes code into it. A
//     W+X region backed by a FILE is not something a runtime does on its own, so it is reported even for
//     an allowlisted process — unless the operator named that file's directory too (below).
//   - ONLY an exe that still exists. `/proc/<pid>/exe` reports "(deleted)" for a process whose binary was
//     unlinked, which is precisely the shape of run-then-replace: start something allowlisted, delete it,
//     and the path keeps vouching for a file nobody can inspect any more.
//   - ONLY an exe that could be identified at all. An empty path means the scan could not read it, and
//     "could not tell" must never resolve to "permitted" (D31).
//
// The list is OPERATOR-SUPPLIED with no built-in defaults. A shipped list of browser paths would be a
// decision made in one place about machines in another, and worse: any attacker who can write a file at
// one of those paths inherits the exemption. Which JITs run on a fleet is something only that fleet's
// operator knows.
//
// TWO THINGS HERE CAME FROM SCANNING A REAL MACHINE RATHER THAN FROM REASONING, and the first version of
// this file got both wrong:
//
//  1. A mapping's "path" is not always a path. Since Linux 5.17 a process can NAME its anonymous
//     mappings, and V8 does: its JIT regions appear as `[anon:JSJITCode]`. Treating a non-empty name as
//     a file would have meant a Node or Chrome process was never explained — the exemption would have
//     silently failed on the single most common JIT on the machine. A mapping is file-backed only if its
//     path is ABSOLUTE; the kernel's bracketed pseudo-names are anonymous memory with a label on it.
//  2. Some runtimes really do map a file W+X. A JVM with class-data sharing maps `classes.jsa` rwxp
//     straight from disk. An absolute rule of "file-backed is always suspicious" would report every JVM
//     forever, which is the noise this allowlist exists to prevent — so an entry may name directories
//     that executable is permitted to map W+X, and nothing else. `/tmp/evil.so` still alerts.

// JITAllowlist is a set of executable paths whose ANONYMOUS W+X regions are expected.
//
// The zero value allows nothing, which is the safe direction: an unconfigured scanner reports every
// suspect rather than silently exempting a set it inferred.
type JITAllowlist struct {
	// paths maps an executable to the directory prefixes it may map W+X FROM DISK. Usually empty: most
	// runtimes only need their anonymous regions explained.
	paths map[string][]string
}

// deletedSuffix is what the kernel appends to /proc/<pid>/exe when the executable has been unlinked.
const deletedSuffix = " (deleted)"

// ParseJITAllowlist reads one entry per line:
//
//	/usr/lib/firefox/firefox
//	/usr/lib/jvm/java-11-openjdk-amd64/bin/java  /usr/lib/jvm/
//
// The first field is the executable. Any further fields are directory prefixes that executable may map
// W+X from disk — for the JVM's class-data-sharing archive and its kind. Blank lines and #-comments are
// ignored.
//
// A RELATIVE PATH IS REFUSED RATHER THAN NORMALISED, in either field. `/proc/<pid>/exe` and a maps
// pathname are both always absolute, so a relative entry can never match anything — it would sit in the
// file looking like protection while exempting nothing, and the operator would discover that only when an
// alert they believed was suppressed arrived, or never.
func ParseJITAllowlist(r io.Reader) (JITAllowlist, error) {
	a := JITAllowlist{paths: map[string][]string{}}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		exe := fields[0]
		if !strings.HasPrefix(exe, "/") {
			return JITAllowlist{}, fmt.Errorf("jit allowlist line %d: %q is not an absolute path, and "+
				"/proc/<pid>/exe always is — this entry could never match, so it would look like an "+
				"exemption while being none", line, exe)
		}
		if strings.HasSuffix(text, deletedSuffix) {
			return JITAllowlist{}, fmt.Errorf("jit allowlist line %d: %q names a DELETED executable, "+
				"which is the shape of run-then-replace and is never a JIT this list should vouch for",
				line, text)
		}
		for _, prefix := range fields[1:] {
			if !strings.HasPrefix(prefix, "/") {
				return JITAllowlist{}, fmt.Errorf("jit allowlist line %d: mapping prefix %q is not "+
					"absolute; a maps pathname always is, so this could never match", line, prefix)
			}
			if prefix == "/" {
				return JITAllowlist{}, fmt.Errorf("jit allowlist line %d: a mapping prefix of \"/\" lets "+
					"%s map ANY file writable and executable, which is the whole exposure this list is "+
					"meant to bound", line, exe)
			}
			a.paths[exe] = append(a.paths[exe], prefix)
		}
		if _, ok := a.paths[exe]; !ok {
			a.paths[exe] = nil
		}
	}
	if err := sc.Err(); err != nil {
		return JITAllowlist{}, err
	}
	return a, nil
}

// LoadJITAllowlist reads an allowlist file. A configured-but-unreadable list is an ERROR, never an empty
// one: silently degrading to "allow nothing" turns every JIT on the machine into an alert, and silently
// degrading to "allow everything" turns the scanner off. Both are decisions the operator did not make.
func LoadJITAllowlist(path string) (JITAllowlist, error) {
	f, err := os.Open(path)
	if err != nil {
		return JITAllowlist{}, err
	}
	defer f.Close()
	return ParseJITAllowlist(f)
}

// Len reports how many executables are exempt, so a caller can say so at startup. An allowlist is a
// deliberate reduction in coverage and belongs in the log next to the scanner that honours it.
func (a JITAllowlist) Len() int { return len(a.paths) }

// Unexplained returns the W+X regions this allowlist does NOT account for.
//
// The name is the contract: it returns what is still suspicious, so a caller that ignores the allowlist
// entirely still behaves correctly (it just reports more). The inverse shape — a boolean "is this process
// allowed" — would have let a caller drop the whole process, file-backed regions included.
func (a JITAllowlist) Unexplained(exe string, regions []Region) []Region {
	prefixes, ok := a.permits(exe)
	if !ok {
		return regions
	}
	var out []Region
	for _, r := range regions {
		if !fileBacked(r.Path) {
			continue // anonymous memory, named or not — what a JIT actually allocates
		}
		if !allowedMapping(r.Path, prefixes) {
			out = append(out, r)
		}
	}
	return out
}

// fileBacked reports whether a mapping comes from a file on disk.
//
// The test is ABSOLUTENESS, not non-emptiness. Linux lets a process name its anonymous mappings and V8
// does — its JIT regions show up as `[anon:JSJITCode]` — so a non-empty pathname is not evidence of a
// file. `[heap]`, `[stack]` and `[vdso]` are the same shape. Getting this wrong means the exemption
// silently fails on the most common JIT on the machine, which is how the first version of this behaved.
func fileBacked(path string) bool { return strings.HasPrefix(path, "/") }

// allowedMapping reports whether a file-backed mapping sits under one of the prefixes this executable was
// granted. A prefix is matched as a DIRECTORY, so /usr/lib/jvm does not vouch for /usr/lib/jvm-evil.
func allowedMapping(path string, prefixes []string) bool {
	for _, p := range prefixes {
		dir := strings.TrimSuffix(p, "/") + "/"
		if strings.HasPrefix(path, dir) {
			return true
		}
	}
	return false
}

// permits reports whether exe is an identified, still-present, listed executable, and the mapping
// prefixes it was granted.
func (a JITAllowlist) permits(exe string) ([]string, bool) {
	if exe == "" || strings.HasSuffix(exe, deletedSuffix) {
		return nil, false
	}
	prefixes, ok := a.paths[exe]
	return prefixes, ok
}
