package main_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/printguard"
)

// buildFilter compiles the real filter binary; these tests run it as CUPS would.
func buildFilter(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "openshield-print-filter")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/lucianoengel/openshield/cmd/openshield-print-filter")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the filter: %v\n%s", err, out)
	}
	return bin
}

// serveVerdict runs a real printguard server returning a fixed verdict, and records what it was asked.
func serveVerdict(t *testing.T, v printguard.Verdict) (socket string, seen *printguard.Request) {
	t.Helper()
	socket = socketPath(t, "p.sock")
	var got printguard.Request
	srv := &printguard.Server{Decide: func(_ context.Context, req printguard.Request) (printguard.Verdict, error) {
		got = req
		return v, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Listen(ctx, socket) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return socket, &got
}

// runFilter invokes the binary with CUPS's argument convention and a job on stdin.
func runFilter(t *testing.T, bin, socket, job string) (stdout string, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(bin, "42", "alice", "Q3 layoffs.docx", "1", "")
	cmd.Env = append(os.Environ(), "OPENSHIELD_PRINT_SOCKET="+socket, "PRINTER=lobby-printer")
	cmd.Stdin = strings.NewReader(job)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running the filter: %v", err)
	}
	return out.String(), errb.String(), exitCode
}

const sensitiveJob = "%!PS\nEmployee CPF 111.444.777-35 salary review\n"

// TestDeniedJobNeverPrints: the enforcement claim. A refused job must produce NO output and a non-zero
// exit, which is what makes CUPS abort it.
//
// Mutation: emit the job anyway on deny → output is non-empty → FAILS.
func TestDeniedJobNeverPrints(t *testing.T) {
	bin := buildFilter(t)
	socket, seen := serveVerdict(t, printguard.VerdictDeny)

	stdout, stderr, code := runFilter(t, bin, socket, sensitiveJob)
	if stdout != "" {
		t.Fatalf("a DENIED job produced %d bytes of output — it would have printed", len(stdout))
	}
	if code == 0 {
		t.Fatal("a DENIED job exited 0 — CUPS only aborts a job on a non-zero exit, so this would print")
	}
	if !strings.Contains(stderr, "REFUSED") {
		t.Errorf("the refusal was not reported to the CUPS job log: %q", stderr)
	}
	// The job metadata reached the engine, and the TITLE did not: a document title is often the sensitive
	// fact itself, so the contract records only whether one existed.
	if seen.Printer != "lobby-printer" || seen.User != "alice" {
		t.Errorf("job metadata = printer %q user %q, want the CUPS-provided values", seen.Printer, seen.User)
	}
	if !seen.HasTitle {
		t.Error("HasTitle is false though CUPS passed a title")
	}
}

// TestAllowedJobIsPassedThroughByteForByte: mediation must not corrupt printing, or the product is worse
// than useless.
func TestAllowedJobIsPassedThroughByteForByte(t *testing.T) {
	bin := buildFilter(t)
	socket, _ := serveVerdict(t, printguard.VerdictAllow)

	// Larger than the filter's internal read buffer, so the head/tail seam is exercised.
	job := sensitiveJob + strings.Repeat("A", 200*1024) + "\n%%EOF\n"
	stdout, _, code := runFilter(t, bin, socket, job)
	if code != 0 {
		t.Fatalf("an ALLOWED job exited %d", code)
	}
	if stdout != job {
		t.Fatalf("the allowed job was altered: got %d bytes, want %d — a filter that changes the job "+
			"corrupts printing", len(stdout), len(job))
	}
}

// TestUnreachableEngineStillPrints is the fail-open property (D17/D73).
//
// Mutation: abort the job when no verdict is available → this FAILS. A DLP that stops an office printing
// because a daemon died gets uninstalled, which protects nothing.
func TestUnreachableEngineStillPrints(t *testing.T) {
	bin := buildFilter(t)
	stdout, stderr, code := runFilter(t, bin, socketPath(t, "absent.sock"), sensitiveJob)
	if code != 0 {
		t.Fatalf("an unreachable engine aborted the job (exit %d) — printing must not depend on the "+
			"agent being alive", code)
	}
	if stdout != sensitiveJob {
		t.Errorf("the job was not passed through on fail-open: %d bytes", len(stdout))
	}
	if !strings.Contains(stderr, "FAILING OPEN") {
		t.Errorf("the fail-open was not reported loudly: %q", stderr)
	}
}

// TestNoSocketConfiguredPassesThrough: an unconfigured filter must be a no-op, not a blocker.
func TestNoSocketConfiguredPassesThrough(t *testing.T) {
	bin := buildFilter(t)
	stdout, _, code := runFilter(t, bin, "", sensitiveJob)
	if code != 0 || stdout != sensitiveJob {
		t.Fatalf("an unconfigured filter altered the job (exit %d, %d bytes)", code, len(stdout))
	}
}
