package doccheck_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/doccheck"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The real README must pass — its honest, negated discussion of the forbidden
// words is exactly what a naive grep punished, and must not be punished here.
func TestREADMEIsHonest(t *testing.T) {
	for _, surface := range doccheck.ClaimSurfaces {
		path := filepath.Join("..", "..", surface)
		v := doccheck.ScanClaimSurface(read(t, path))
		if len(v) != 0 {
			t.Errorf("%s flagged as overclaiming, but its uses are honest negations:\n", surface)
			for _, x := range v {
				t.Errorf("  %s", x)
			}
		}
	}
}

// Both directions, from fixtures: the good surface passes, the bad one fails —
// so the check is proven to catch a planted overclaim, not merely to pass today.
func TestClaimSurfaceFixtures(t *testing.T) {
	if v := doccheck.ScanClaimSurface(read(t, "testdata/good.md")); len(v) != 0 {
		t.Errorf("good fixture flagged: %v", v)
	}
	bad := doccheck.ScanClaimSurface(read(t, "testdata/bad.md"))
	if len(bad) == 0 {
		t.Fatal("bad fixture ('provides tamper-proof audit logs') was NOT flagged — the check " +
			"does not catch the thing it exists for")
	}
	// It should catch the tamper-proof claim specifically.
	var sawTamperProof bool
	for _, v := range bad {
		if v.Term == "tamper-proof" || v.Term == "tamperproof" {
			sawTamperProof = true
		}
	}
	if !sawTamperProof {
		t.Errorf("bad fixture flagged %v, but not the tamper-proof claim", bad)
	}
}

// Negation and the escape both suppress a flag.
func TestQualifiedUsesPass(t *testing.T) {
	negated := "The log is not tamper-proof and cannot prevent exfiltration."
	if v := doccheck.ScanClaimSurface(negated); len(v) != 0 {
		t.Errorf("a negated line was flagged: %v", v)
	}
	escaped := "We call it unhackable here on purpose. <!-- allow: unhackable -->"
	if v := doccheck.ScanClaimSurface(escaped); len(v) != 0 {
		t.Errorf("an escaped line was flagged: %v", v)
	}
	// But an unqualified claim on its own line is caught.
	claim := "OpenShield is fully secure."
	if v := doccheck.ScanClaimSurface(claim); len(v) == 0 {
		t.Error("an unqualified 'fully secure' claim was not caught")
	}
}

// The real register has unique D-numbers; a collision fixture fails.
func TestDecisionRegisterUnique(t *testing.T) {
	if err := doccheck.CheckDecisionRegister(read(t, filepath.Join("..", "..", "docs", "decisions.md"))); err != nil {
		t.Errorf("the real decision register has a problem: %v", err)
	}
	if err := doccheck.CheckDecisionRegister(read(t, "testdata/dupe_register.md")); err == nil {
		t.Fatal("a register with a duplicate D-number passed — the anti-drift guard is not working")
	}
}
