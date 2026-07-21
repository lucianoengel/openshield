//go:build linux

package fanotify_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/connectors/fanotify"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

const dsn = "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable"

// A REAL file change produces an event with the right path — unprivileged, here.
func TestWatchRealFile(t *testing.T) {
	dir := t.TempDir()
	w, err := fanotify.Open(dir)
	if err != nil {
		t.Skipf("LOUD SKIP: fanotify notify mode unavailable (%v)", err)
	}
	defer w.Close()

	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("x"), 0o600)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ev, err := w.Next(ctx)
	if err != nil {
		t.Fatalf("no event for a real file write: %v", err)
	}
	if got := ev.GetFilesystem().GetResolvedPath(); got != filepath.Join(dir, "hello.txt") {
		t.Errorf("path = %q, want %q", got, filepath.Join(dir, "hello.txt"))
	}
}

// A real file change → connector event → engine (real worker + Postgres) →
// verifiable audit. A genuine kernel-event → audit run, UNPRIVILEGED, here.
func TestFanotifyToAudit(t *testing.T) {
	ctx := context.Background()
	// Postgres availability.
	l, err := postgres.OpenForVerify(ctx, dsn)
	if err != nil {
		if os.Getenv("OPENSHIELD_REQUIRE_POSTGRES") != "" {
			t.Fatalf("POSTGRES REQUIRED: %v", err)
		}
		t.Skipf("LOUD SKIP: Postgres unavailable (%v)", err)
	}
	l.Close()
	clean(t)

	dir := t.TempDir()
	w, err := fanotify.Open(dir)
	if err != nil {
		t.Skipf("LOUD SKIP: fanotify unavailable (%v)", err)
	}
	defer w.Close()

	// Build + start the worker, open the ledger, assemble the engine.
	worker := startWorker(t)
	defer worker.Close()
	signer, _ := core.NewSigner()
	ledger, err := postgres.Open(ctx, dsn, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	pol, _ := policy.NewDefault(ctx)
	eng := engine.New(worker, pol, ledger, nil, 10*time.Second)

	// Write a file with a seeded CPF into the watched dir.
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = os.WriteFile(filepath.Join(dir, "customers.csv"), []byte("name,cpf\nalice,111.444.777-35\n"), 0o600)
	}()
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ev, err := w.Next(wctx)
	if err != nil {
		t.Fatalf("no fanotify event: %v", err)
	}
	ev.EventId = "fan-e2e" // stable id for assertion

	dec, err := eng.Process(ctx, ev)
	if err != nil {
		t.Fatalf("engine.Process: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALERT {
		t.Fatalf("decision = %v, want ALERT for a CPF file", dec.GetAction())
	}
	res, err := ledger.Verify(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Consistent || res.Entries < 1 {
		t.Fatalf("ledger not consistent after fanotify→audit: %s", res)
	}
	t.Logf("fanotify → audit OK (unprivileged): real file change → ALERT → verifiable ledger (%s)", res)
}

func startWorker(t *testing.T) *privileged.Worker {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "openshield-worker")
	if out, err := exec.Command("go", "build", "-o", bin, "../../../cmd/openshield-worker").CombinedOutput(); err != nil {
		t.Fatalf("building worker: %v\n%s", err, out)
	}
	w, err := privileged.StartWorker(context.Background(), bin)
	if err != nil {
		t.Fatal(err)
	}
	return w
}
