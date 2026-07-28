package fitness_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A UNIX SOCKET UNDER t.TempDir() IS A macOS FAILURE WAITING FOR A LONG TEST NAME (D324).
//
// `sockaddr_un.sun_path` holds 104 bytes on macOS and 108 on Linux, and the kernel does not truncate an
// over-long address — it refuses the bind with EINVAL, surfaced as "bind: invalid argument". That message
// names neither the length nor the cause, so it reads as a broken socket.
//
// `t.TempDir()` builds its path from the TEST'S NAME. On a macOS runner the temp prefix alone is about 48
// bytes (`/var/folders/8j/sfr9qqcj73j4p6nhwcfpr0th0000gn/T/`), which leaves roughly 31 bytes for the name
// before the address overflows. So the rule this guard enforces has a genuinely perverse shape: a
// DESCRIPTIVE test name breaks the test, and a terse one hides the bug until someone renames it.
//
// It is not hypothetical. `TestMismatchedResponseIDIsRejected` — 33 characters — took the macOS CI job
// down for over a day while every Linux run stayed green, on a machine nobody here develops on. A
// constraint enforced only by a platform you do not run is discovered by someone who did not write the
// code, long after they could have connected it to a change.
//
// The fix is a per-package `socketPath` helper that allocates outside the test-named directory AND
// asserts the length, so the failure lands on the author's own machine. This guard is what stops the
// original shape from coming back.
//
// HONEST LIMIT: it matches the SHAPE on one line, so a socket path assembled across two statements — a
// `dir := t.TempDir()` here and a `filepath.Join(dir, "x.sock")` there — walks straight past it. That is
// accepted rather than solved: catching it properly needs type-aware analysis, and the length assertion
// inside `socketPath` is the check that actually holds, on every platform, whatever route the path took.
// This guard's job is narrower — to stop the exact idiom that shipped the bug from being copied again.
var socketUnderTempDir = regexp.MustCompile(`TempDir\(\)[^\n]{0,40}\.sock`)

func TestNoUnixSocketIsBuiltFromATestNamedTempDir(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string
	checked := 0

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		for i, line := range strings.Split(string(b), "\n") {
			// Comments are stripped before matching. Without it this guard flags its own explanation of
			// the idiom it forbids — the same false positive D37's claim-surface check hit, where a
			// discipline that must DISCUSS a forbidden phrase gets caught by the grep enforcing it.
			if socketUnderTempDir.MatchString(stripLineComment(line)) {
				offenders = append(offenders, filepath.ToSlash(path)+":"+itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no _test.go files were scanned — this guard would pass on an empty tree, which is how a " +
			"check comes to mean nothing")
	}
	if len(offenders) > 0 {
		t.Errorf("a unix socket path is built from t.TempDir(), which embeds the TEST NAME and overflows "+
			"the %d-byte macOS address limit once that name passes ~31 characters. Use the package's "+
			"socketPath helper, which allocates outside the test-named directory and asserts the length "+
			"so the failure lands here rather than on a macOS runner:\n  %s",
			104, strings.Join(offenders, "\n  "))
	}
}

// stripLineComment drops a // comment so prose about the rule is not mistaken for a breach of it.
// Crude about a "//" inside a string literal, which is harmless here: what survives is still the code.
func stripLineComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
