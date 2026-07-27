//go:build integration

package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestMain removes the shared Postgres and the build directory after the last scenario. A t.Cleanup would
// tear the database down after the FIRST one, and every later scenario would start its own — silently
// restoring the churn this exists to remove, while still passing.
//
// IT LIVES IN A _test.go FILE, and that is not a style preference — it is the whole reason it runs (D313).
// This function sat in `harness.go`, an ORDINARY source file, for four rounds. `go test` only recognises
// TestMain in a _test.go file, so in a plain file it is just a function with a suggestive name that
// nothing calls. It compiled, it read correctly, it was never invoked, and no test could fail because of
// it: the only evidence was on the HOST, where 33 Postgres containers and 25GB of build directories had
// accumulated until the root filesystem filled and the gate failed to LINK.
//
// The lesson generalises past this bug. A cleanup path is the one kind of code whose absence produces no
// failing test by construction — everything it was supposed to tidy up is, by definition, not what the
// suite asserts on. It needs a guard that watches the machine, which is what TestTheSuiteCleansUpAfterItself
// below does.
func TestMain(m *testing.M) {
	code := m.Run()
	if sharedPGName != "" {
		_ = exec.Command("podman", "rm", "-f", sharedPGName).Run()
	}
	// REMOVE THE BUILD DIRECTORY (D313). It holds every command in the tree — 196MB — and until this
	// existed the suite left one behind on every run, named uniquely so they accumulated rather than
	// overwriting. 130 of them had built up: 25GB, which filled the root filesystem and turned the gate
	// red with "no space left on device" on a tree whose code was fine.
	//
	// This is the failure mode a test suite is least likely to catch about itself. Every run passed; the
	// damage was to the MACHINE, and it landed on whoever ran the suite next — which on a shared host is
	// somebody else. A suite that degrades its host is one people stop running.
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// TestTheSuiteCleansUpAfterItself is the guard for the class of bug that hid TestMain (D313).
//
// It runs LAST by name (Go runs tests in source order within a file, and this is the only test in this
// one — but the real ordering guarantee is that it asserts on state that accumulates, so an early run
// simply sees fewer leftovers). What it checks is the MACHINE, not the product: containers this suite
// started and build directories it created, belonging to runs that have already finished.
//
// A cleanup path cannot be tested by asserting that cleanup happened at the end of THIS process — the
// cleanup runs after every test does, including this one. So it asserts the opposite thing and the more
// useful one: that PREVIOUS runs left nothing behind. If TestMain stops running again, the second run
// after the breakage fails, naming exactly what leaked.
func TestTheSuiteCleansUpAfterItself(t *testing.T) {
	out, err := exec.Command("podman", "ps", "-a", "--format", "{{.Names}}").Output()
	if err != nil {
		t.Skipf("podman is not available to check for leaked containers: %v", err)
	}
	var leaked []string
	for _, name := range strings.Fields(string(out)) {
		// Only this suite's containers, and only ones this process did not start.
		if strings.HasPrefix(name, containerPrefix) && name != sharedPGName {
			leaked = append(leaked, name)
		}
	}
	if len(leaked) > 0 {
		t.Errorf("%d container(s) from EARLIER runs of this suite are still running: %v\n"+
			"Each is a Postgres holding memory and a port. 33 of these had accumulated before D313, "+
			"because TestMain lived in harness.go — an ordinary source file, where the testing framework "+
			"never calls it. Nothing failed; the damage was to the host.", len(leaked), leaked)
	}

	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("reading %s: %v", os.TempDir(), err)
	}
	var dirs []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), buildDirPrefix) && (binDir == "" ||
			e.Name() != strings.TrimPrefix(binDir, os.TempDir()+"/")) {
			dirs = append(dirs, e.Name())
		}
	}
	if len(dirs) > 0 {
		t.Errorf("%d build director(ies) from EARLIER runs are still in %s: %v\n"+
			"Each holds every command in the tree (~196MB). 130 had accumulated, filling the root "+
			"filesystem, and the symptom was the gate failing to LINK with 'no space left on device' on a "+
			"tree whose code was fine.", len(dirs), os.TempDir(), dirs)
	}
}
