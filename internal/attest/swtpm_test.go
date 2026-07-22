package attest

import (
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"
)

// requireSWTPM skips the test unless the swtpm software-TPM binary is installed.
// This mirrors requireDB in the Postgres tests: the attest suite runs for real
// wherever swtpm is present (local dev and a CI job that installs it) and is
// cleanly skipped elsewhere, so its absence is never a false green.
func requireSWTPM(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed; skipping TPM attestation test")
	}
}

// startSWTPM spawns a swtpm software TPM on a TCP socket in a temp state dir,
// connects to it, runs TPM2_Startup, and returns an open TPM. The swtpm process
// and the connection are torn down at test end.
func startSWTPM(t *testing.T) *TPM {
	t.Helper()
	requireSWTPM(t)

	serverPort := freePort(t)
	ctrlPort := freePort(t)
	state := t.TempDir()

	cmd := exec.Command("swtpm", "socket",
		"--tpm2",
		"--server", fmt.Sprintf("type=tcp,port=%d", serverPort),
		"--ctrl", fmt.Sprintf("type=tcp,port=%d", ctrlPort),
		"--tpmstate", "dir="+state,
		"--flags", "not-need-init",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swtpm: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	addr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	tpm := dialWithRetry(t, addr)
	if err := tpm.Startup(); err != nil {
		t.Fatalf("swtpm startup: %v", err)
	}
	return tpm
}

// dialWithRetry waits for the freshly-spawned swtpm to accept connections.
func dialWithRetry(t *testing.T, addr string) *TPM {
	t.Helper()
	var lastErr error
	for i := 0; i < 100; i++ {
		tpm, err := Open(addr)
		if err == nil {
			t.Cleanup(func() { _ = tpm.Close() })
			return tpm
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("connect to swtpm at %s: %v", addr, lastErr)
	return nil
}

// freePort reserves an ephemeral port and releases it for swtpm to bind. There
// is a small reuse race, but swtpm binds immediately on start.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}
