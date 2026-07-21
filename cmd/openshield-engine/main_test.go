package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildEngine builds the actual openshield-engine binary — the shipped artifact.
func buildEngine(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "openshield-engine")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("building engine: %v\n%s", err, out)
	}
	return bin
}

// 2.2 — the engine binary started with no watch directories exits non-zero
// rather than running as a silent no-op. Config is validated FIRST, so this needs
// no Postgres.
func TestEngineRefusesNoWatchDirs(t *testing.T) {
	bin := buildEngine(t)
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "OPENSHIELD_WATCH_DIRS=")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("engine with no watch dirs exited 0 — a silent no-op; output:\n%s", out)
	}
	if !strings.Contains(string(out), "OPENSHIELD_WATCH_DIRS") {
		t.Errorf("expected the error to name OPENSHIELD_WATCH_DIRS, got:\n%s", out)
	}
}
