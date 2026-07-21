package engine_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

const dsn = "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable"

func requirePG(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l, err := postgres.OpenForVerify(ctx, dsn)
	if err != nil {
		if os.Getenv("OPENSHIELD_REQUIRE_POSTGRES") != "" {
			t.Fatalf("POSTGRES REQUIRED but unavailable: %v", err)
		}
		t.Skipf("LOUD SKIP: Postgres unavailable (%v) — the walking skeleton is NOT verified", err)
	}
	l.Close()
	// clean slate
	pool := mustPool(t)
	defer pool.Close()
	_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS investigation_views, agent_identities, enrollment_tokens, fleet_telemetry, audit_entries, key_epochs, anchors, schema_migrations CASCADE`)
}

func buildWorker(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "openshield-worker")
	out, err := exec.Command("go", "build", "-o", bin, "../../cmd/openshield-worker").CombinedOutput()
	if err != nil {
		t.Fatalf("building worker: %v\n%s", err, out)
	}
	return bin
}

func fsEvent(id, path string) *corev1.Event {
	return &corev1.Event{
		EventId: id, Purpose: corev1.Purpose_PURPOSE_DLP, Kind: corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: path}}},
	}
}

// The walking skeleton: a file with a seeded CPF flows through the REAL worker
// binary → policy → decision → REAL Postgres ledger, landing a verifiable entry.
func TestWalkingSkeleton(t *testing.T) {
	requirePG(t)
	ctx := context.Background()

	// A file with a valid CPF (111.444.777-35).
	dir := t.TempDir()
	file := filepath.Join(dir, "customers.csv")
	if err := os.WriteFile(file, []byte("name,cpf\nalice,111.444.777-35\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	worker, err := privileged.StartWorker(ctx, buildWorker(t))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	signer, _ := core.NewSigner()
	ledger, err := postgres.Open(ctx, dsn, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	pol, err := policy.NewDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}

	eng := engine.New(worker, pol, ledger, nil, 10*time.Second)

	dec, err := eng.Process(ctx, fsEvent("evt-cpf", file))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALERT {
		t.Fatalf("decision = %v, want ALERT for a file with a CPF", dec.GetAction())
	}

	// The audit ledger has a verifiable entry recording it.
	res, err := ledger.Verify(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Consistent || res.Entries < 1 {
		t.Fatalf("ledger not consistent/empty after the skeleton ran: %s", res)
	}
	t.Logf("walking skeleton OK: CPF file → ALERT → verifiable ledger (%s)", res)
}

// --- content-free and error paths, without a real worker (fake classifier) ---

type fakeWorker struct {
	hits []*corev1.DetectorHit
	err  error
}

func (f fakeWorker) Classify(_ context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &corev1.ClassifyResponse{RequestId: req.GetRequestId(), EventId: req.GetEventId(), Hits: f.hits}, nil
}

type recLedger struct{ entries []*core.Entry }

func (l *recLedger) Append(_ context.Context, e *core.Entry) error {
	cp := *e
	l.entries = append(l.entries, &cp)
	return nil
}
func (l *recLedger) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{Consistent: true}, nil
}
func (l *recLedger) Close() error { return nil }

// The classification built from worker hits carries NO matched text (D29).
func TestNoContentInPipeline(t *testing.T) {
	fw := fakeWorker{hits: []*corev1.DetectorHit{
		{DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF, Confidence: 0.95, Count: 2},
	}}
	// A capturing policy stage that inspects the State the classify stage built.
	var captured *corev1.LocalClassification
	capture := stageFunc("policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
		captured = s.Classification
		return core.Decided(&corev1.Decision{DecisionId: "d", EventId: s.Event.GetEventId(), Action: corev1.Action_ACTION_ALERT}), nil
	})
	eng := engine.New(fw, capture, &recLedger{}, nil, time.Second)
	if _, err := eng.Process(context.Background(), fsEvent("e1", "/tmp/x")); err != nil {
		t.Fatal(err)
	}
	if captured == nil || len(captured.GetMatches()) != 2 {
		t.Fatalf("expected 2 matches from count=2, got %v", captured)
	}
	for _, m := range captured.GetMatches() {
		if m.GetMatchedText() != "" {
			t.Errorf("a match carried content %q — no content may cross the worker boundary (D29)", m.GetMatchedText())
		}
	}
}

// A worker error terminates as a failure, not a clean "nothing found" result.
func TestWorkerErrorIsAuditable(t *testing.T) {
	fw := fakeWorker{err: errors.New("worker crashed")}
	led := &recLedger{}
	eng := engine.New(fw, stageFunc("policy", func(context.Context, *core.State) (core.Outcome, error) {
		t.Error("policy ran despite a classify failure")
		return core.Continue(), nil
	}), led, nil, time.Second)

	_, err := eng.Process(context.Background(), fsEvent("e2", "/tmp/x"))
	if err == nil {
		t.Fatal("a worker error produced no error — a failed parse must not read as a clean result")
	}
	// The failure was recorded (an outcome, not silence).
	if len(led.entries) != 1 {
		t.Errorf("worker failure recorded %d entries, want 1 (a failure is auditable)", len(led.entries))
	}
}
