package quarantine_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/quarantine"
)

func quarantineDecision() *corev1.Decision {
	return &corev1.Decision{Action: corev1.Action_ACTION_QUARANTINE_LOCAL}
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func quarantinedNames(t *testing.T, qdir string) []string {
	t.Helper()
	entries, err := os.ReadDir(qdir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// The enforcer's PRIMARY function had no test. The package's only test covered the symlink refusal, so
// "does quarantine actually contain a flagged file" was never asserted.
func TestAFlaggedFileIsMovedIntoQuarantine(t *testing.T) {
	root := t.TempDir()
	qdir := filepath.Join(root, "q")
	src := writeFile(t, filepath.Join(root, "work", "customers.csv"), "CPF 529.982.247-25")

	if err := quarantine.New(qdir).EnforceTarget(context.Background(), quarantineDecision(), src); err != nil {
		t.Fatalf("EnforceTarget: %v", err)
	}

	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("the flagged file is still at its original path — it was copied, not contained")
	}
	got := quarantinedNames(t, qdir)
	if len(got) != 1 || got[0] != "customers.csv" {
		t.Fatalf("quarantine holds %v, want [customers.csv]", got)
	}
	content, err := os.ReadFile(filepath.Join(qdir, "customers.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "CPF 529.982.247-25" {
		t.Fatalf("quarantined content is %q — containment must preserve the evidence", content)
	}

	// Owner-only: quarantined files are by definition the sensitive ones, so the directory holding them
	// must not be readable by other local accounts.
	fi, err := os.Stat(qdir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("quarantine directory is mode %04o — readable by group or other", perm)
	}
}

// THE BUG. Two flagged files sharing a base name is the NORMAL case for DLP: what gets flagged is exactly
// the recurring names — customers.csv, resume.pdf, export.xlsx — in different directories.
//
// Before the fix the destination was dstDir/Base(src) with an unconditional rename over it, so the second
// quarantine silently destroyed the first: both calls returned nil, the ledger recorded two containments,
// and the directory held one file. The first file had already been moved out of its original location, so
// its content was gone, and an investigator opening customers.csv would be reading the other one.
func TestQuarantiningTwoFilesWithTheSameNameKeepsBoth(t *testing.T) {
	root := t.TempDir()
	qdir := filepath.Join(root, "q")
	enf := quarantine.New(qdir)

	sources := map[string]string{
		filepath.Join(root, "finance", "customers.csv"): "FINANCE ROWS",
		filepath.Join(root, "sales", "customers.csv"):   "SALES ROWS",
		filepath.Join(root, "hr", "customers.csv"):      "HR ROWS",
	}
	var paths []string
	for p := range sources {
		paths = append(paths, p)
	}
	sort.Strings(paths) // deterministic order
	for _, p := range paths {
		writeFile(t, p, sources[p])
		if err := enf.EnforceTarget(context.Background(), quarantineDecision(), p); err != nil {
			t.Fatalf("EnforceTarget(%s): %v", p, err)
		}
	}

	names := quarantinedNames(t, qdir)
	if len(names) != 3 {
		t.Fatalf("quarantine holds %d files (%v), want 3 — a containment that reports success while "+
			"destroying an earlier one is worse than a failure, because the ledger records both", len(names), names)
	}

	// Every original content must still be readable somewhere in quarantine.
	found := map[string]bool{}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(qdir, n))
		if err != nil {
			t.Fatal(err)
		}
		found[string(b)] = true
	}
	for _, want := range sources {
		if !found[want] {
			t.Fatalf("the content %q is not in quarantine; it was overwritten by a later file of the same "+
				"name and is now unrecoverable: quarantine holds %v", want, names)
		}
	}

	// The first keeps the plain name; later ones are suffixed so a human can read the listing.
	if names[0] != "customers.1.csv" && names[0] != "customers.csv" {
		t.Fatalf("unexpected naming scheme: %v", names)
	}
}

// A non-regular source is refused at enforce time (D65). The symlink case has its own test; these are the
// other shapes something could be swapped to between classification and enforcement.
func TestNonRegularSourcesAreRefused(t *testing.T) {
	root := t.TempDir()
	qdir := filepath.Join(root, "q")
	enf := quarantine.New(qdir)

	dir := filepath.Join(root, "adirectory")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	targets := map[string]string{
		"directory":    dir,
		"missing file": filepath.Join(root, "absent"),
		"empty target": "",
	}
	// The fifo case lives behind mkfifoTarget, which is build-tagged: syscall.Mkfifo does not exist on
	// Windows, and this file has to vet there. `make quick` cross-compiles with `go build`, which does NOT
	// compile test files, so the first version of this test passed locally and failed `go vet ./...` on the
	// windows runner.
	if fifo := mkfifoTarget(t, root); fifo != "" {
		targets["fifo"] = fifo
	}

	for name, target := range targets {
		t.Run(name, func(t *testing.T) {
			if err := enf.EnforceTarget(context.Background(), quarantineDecision(), target); err == nil {
				t.Fatalf("quarantine accepted a %s and reported success", name)
			}
		})
	}
	if names := quarantinedNames(t, qdir); len(names) != 0 {
		t.Fatalf("refused targets still left %v in quarantine", names)
	}
}

// A no-op enforcement is a containment that did not happen but looks like it did.
func TestATargetlessEnforceIsAnError(t *testing.T) {
	if err := quarantine.New(t.TempDir()).Enforce(context.Background(), quarantineDecision()); err == nil {
		t.Fatal("a targetless Enforce reported success — the ledger would record a containment that " +
			"never moved a file")
	}
}

func TestCapabilitiesClaimsOnlyQuarantine(t *testing.T) {
	var e core.Enforcer = quarantine.New(t.TempDir())
	caps := e.Capabilities()
	if len(caps) != 1 || caps[0] != corev1.Action_ACTION_QUARANTINE_LOCAL {
		t.Fatalf("Capabilities() = %v, want exactly [QUARANTINE_LOCAL]", caps)
	}
}
