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
	if testing.Short() {
		t.Skip("skipping compile test in -short mode")
	}

	src, err := os.ReadFile(filepath.Join("testdata", "enforcerisolation", "bad_enforcer.go.txt"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	// Build inside the real module so the import path resolves.
	dir := t.TempDir()
	pkgDir := filepath.Join("testdata", "tmp_enforcerisolation")
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
		t.Fatalf("fixture COMPILED — enforcer isolation is not enforced by the type "+
			"system. An enforcer can reach classifier internals.\noutput:\n%s", out)
	}

	// Assert the failure is the one we intend. Without this, an unrelated
	// breakage (typo, moved package) would make the test pass vacuously.
	got := string(out)
	wantAny := []string{
		"does not implement core.Enforcer",
		"wrong type for method Enforce",
		"have Enforce(context.Context, *corev1.Decision, *corev1.LocalClassification) error",
	}
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
	t.Logf("enforcer isolation confirmed by compiler rejection:\n%s", strings.TrimSpace(got))
}
