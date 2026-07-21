package main

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
	"github.com/lucianoengel/openshield/internal/policy"
)

// recLedger records appended entries so the test can assert an enforcement outcome.
type recLedger struct{ entries []*core.Entry }

func (r *recLedger) Append(_ context.Context, e *core.Entry) error {
	r.entries = append(r.entries, e)
	return nil
}
func (r *recLedger) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{}, nil
}
func (r *recLedger) Close() error { return nil }

// fakeWorker classifies any content as a CPF hit, so a QUARANTINE policy fires without a
// real worker process — this test targets the ENFORCER WIRING, not classification.
type fakeWorker struct{}

func (fakeWorker) Classify(_ context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	return &corev1.ClassifyResponse{
		RequestId: req.GetRequestId(), EventId: req.GetEventId(),
		Hits: []*corev1.DetectorHit{{DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF, Confidence: 0.95, Count: 1}},
	}, nil
}

const quarantinePolicy = `package openshield
import rego.v1
hit if { some h in input.classification; h.type == "DETECTOR_TYPE_CPF" }
decision := {"action":"QUARANTINE_LOCAL","reason":"cpf"} if { hit }
decision := {"action":"ALLOW","reason":"clean"} if { not hit }`

func fsEvent(id, path string) *corev1.Event {
	return &corev1.Event{
		EventId: id, Kind: corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: path}}},
	}
}

func buildEngine(t *testing.T, led core.Ledger) *engine.Engine {
	t.Helper()
	pol, err := policy.New(context.Background(), "q", "1", quarantinePolicy)
	if err != nil {
		t.Fatal(err)
	}
	return engine.New(fakeWorker{}, pol, led, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Second)
}

// HON-3: with OPENSHIELD_ENFORCE set, registerEnforcers wires the quarantine enforcer and a
// QUARANTINE_LOCAL decision MOVES the file and audits an "enforced" outcome — production can
// now contain, not only observe.
func TestEnforceFlagQuarantinesFile(t *testing.T) {
	dir := t.TempDir()
	qdir := filepath.Join(dir, "quarantine")
	file := filepath.Join(dir, "customers.csv")
	if err := os.WriteFile(file, []byte("cpf 111.444.777-35"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("OPENSHIELD_ENFORCE", "1")
	t.Setenv("OPENSHIELD_QUARANTINE_DIR", qdir)

	led := &recLedger{}
	eng := buildEngine(t, led)
	if err := registerEnforcers(eng, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if len(eng.Enforcers) == 0 {
		t.Fatal("no enforcers registered under OPENSHIELD_ENFORCE — HON-3 wiring missing")
	}

	if _, err := eng.Process(context.Background(), fsEvent("e1", file)); err != nil {
		t.Fatal(err)
	}
	// The file was MOVED out of its original path into quarantine.
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("the flagged file is still at its original path — it was not quarantined")
	}
	if entries, _ := filepath.Glob(filepath.Join(qdir, "*")); len(entries) == 0 {
		t.Errorf("nothing was moved into the quarantine dir")
	}
	// An "enforced" outcome was audited.
	enforced := false
	for _, e := range led.entries {
		if e.OutcomeKind == "enforced" {
			enforced = true
		}
	}
	if !enforced {
		t.Error("no 'enforced' outcome was audited")
	}
}

// HON-3: WITHOUT the flag, no enforcer is registered and the file is untouched (observe-only
// default preserved, D1).
func TestObserveOnlyByDefault(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "customers.csv")
	if err := os.WriteFile(file, []byte("cpf 111.444.777-35"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Unsetenv("OPENSHIELD_ENFORCE")

	led := &recLedger{}
	eng := buildEngine(t, led)
	if err := registerEnforcers(eng, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if len(eng.Enforcers) != 0 {
		t.Fatalf("enforcers registered without OPENSHIELD_ENFORCE — observe-only default broken: %d", len(eng.Enforcers))
	}
	if _, err := eng.Process(context.Background(), fsEvent("e1", file)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("observe-only: the file was touched (%v) — a decision was recorded but must not enforce", err)
	}
}
