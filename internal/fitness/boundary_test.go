package fitness_test

import (
	"os"
	"os/exec"
	"testing"
)

// TestCapabilityBoundaryCheckExists asserts the import-direction guard exists and
// passes. Without this, someone could delete the script and the "core depends on
// no capability" claim would silently lose its enforcement while everything still
// went green.
func TestCapabilityBoundaryCheckExists(t *testing.T) {
	const script = "../../scripts/check-capability-boundary.sh"
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("the capability-boundary check is missing (%v) — the core-depends-on-no-"+
			"capability claim would be unenforced", err)
	}
	cmd := exec.Command("bash", "scripts/check-capability-boundary.sh")
	cmd.Dir = "../.." // run from repo root so `go list` resolves
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("capability-boundary check failed:\n%s", out)
	}
}
