package core_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnforcerIsolationFailsToCompile proves that an enforcer cannot receive
// classifier output.
//
// The requirement is "an enforcer CANNOT see classifier internals". A test that
// merely checks no current enforcer does so would prove "does not today". The
// only faithful test of *cannot* is a compilation that cannot succeed, so this
// builds a fixture that tries and asserts the compiler rejects it.
//
// The design doc flags the obvious hazard: negative compile tests can pass for
// the wrong reason. A typo, a missing import, a renamed package — any of those
// also fail to compile, and the test would report success while proving
// nothing. So this asserts on the SPECIFIC compiler error, not merely on a
// non-zero exit.
func TestEnforcerIsolationFailsToCompile(t *testing.T) {
	mustNotCompile(t, "bad_enforcer.go.txt", []string{
		"does not implement core.Enforcer",
		"wrong type for method Enforce",
	})
}

// TestTransportRejectsLocalClassification proves the wire boundary cannot carry
// the host-only classification form. Same mechanism, same reason: a missing
// method is a compile error, a redaction step is a runtime behaviour.
func TestTransportRejectsLocalClassification(t *testing.T) {
	mustNotCompile(t, "bad_transport.go.txt", []string{
		"cannot use lc",
		"LocalClassification",
	})
}

// mustNotCompile builds a fixture that is expected to FAIL, and asserts the
// failure is the intended one. Without the message check an unrelated breakage
// (a typo, a moved package) would make these tests pass while proving nothing.
func mustNotCompile(t *testing.T, fixture string, wantAny []string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping compile test in -short mode")
	}

	src, err := os.ReadFile(filepath.Join("testdata", "enforcerisolation", fixture))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	// Build inside the real module so the import path resolves.
	dir := t.TempDir()
	pkgDir := filepath.Join("testdata", "tmp_"+strings.TrimSuffix(fixture, ".go.txt"))
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkgDir) })

	target := filepath.Join(pkgDir, "bad_enforcer.go")
	if err := os.WriteFile(target, src, 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "out"), "./"+filepath.ToSlash(pkgDir))
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatalf("fixture %s COMPILED — the boundary it tests is not enforced by the "+
			"type system.\noutput:\n%s", fixture, out)
	}

	got := string(out)
	matched := false
	for _, w := range wantAny {
		if strings.Contains(got, w) {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("fixture failed to compile, but NOT for the expected reason.\n"+
			"This test would otherwise pass vacuously.\nwant one of: %v\ngot:\n%s",
			wantAny, got)
	}
	t.Logf("%s: boundary confirmed by compiler rejection:\n%s", fixture, strings.TrimSpace(got))
}
