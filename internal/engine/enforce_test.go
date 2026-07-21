package engine_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/quarantine"
	"github.com/lucianoengel/openshield/internal/engine"
)

// A policy stage that emits a fixed action.
func decideStage(action corev1.Action) core.Stage {
	return stageFunc("policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
		return core.Decided(&corev1.Decision{
			DecisionId: "d", EventId: s.Event.GetEventId(), Action: action,
		}), nil
	})
}

type fakeMover struct {
	moves [][2]string
	err   error
}

func (m *fakeMover) Move(src, dstDir string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	m.moves = append(m.moves, [2]string{src, dstDir})
	return filepath.Join(dstDir, filepath.Base(src)), nil
}

func engineWith(led core.Ledger, action corev1.Action, enforcers ...core.Enforcer) *engine.Engine {
	e := engine.New(fakeWorker{}, decideStage(action), led, nil, time.Second)
	e.Enforcers = enforcers
	return e
}

// No enforcers → decide + record, enforce nothing (observe-only default, D1).
func TestObserveOnlyByDefault(t *testing.T) {
	led := &recLedger{}
	e := engineWith(led, corev1.Action_ACTION_QUARANTINE_LOCAL) // no enforcers
	mover := &fakeMover{}
	_ = mover
	if _, err := e.Process(context.Background(), fsEvent("e1", "/tmp/f")); err != nil {
		t.Fatal(err)
	}
	// Exactly one entry: the decision. No enforcement entry.
	if len(led.entries) != 1 {
		t.Fatalf("entries = %d, want 1 (decision only, no enforcement) — observe-only default", len(led.entries))
	}
	if led.entries[0].OutcomeKind == "enforced" || led.entries[0].OutcomeKind == "enforcement-failed" {
		t.Error("an enforcement outcome was recorded with no enforcers registered")
	}
}

// A QUARANTINE_LOCAL decision → file moved, decision + enforcement recorded, in
// that order (decision first).
func TestEnforcementDispatchedAndAudited(t *testing.T) {
	led := &recLedger{}
	mover := &fakeMover{}
	enf := quarantine.WithMover("/quarantine", mover)
	e := engineWith(led, corev1.Action_ACTION_QUARANTINE_LOCAL, enf)

	if _, err := e.Process(context.Background(), fsEvent("e1", "/home/alice/leak.csv")); err != nil {
		t.Fatal(err)
	}
	if len(mover.moves) != 1 || mover.moves[0][0] != "/home/alice/leak.csv" {
		t.Fatalf("file not moved to quarantine: %v", mover.moves)
	}
	if len(led.entries) != 2 {
		t.Fatalf("entries = %d, want 2 (decision then enforcement)", len(led.entries))
	}
	// Order: decision recorded BEFORE the enforcement outcome.
	if led.entries[0].OutcomeKind == "enforced" {
		t.Error("enforcement was recorded before the decision — record must precede enforce")
	}
	if led.entries[1].OutcomeKind != "enforced" {
		t.Errorf("second entry = %q, want 'enforced'", led.entries[1].OutcomeKind)
	}
}

// An enforcer error → a high-severity enforcement-failed audit, not swallowed.
func TestEnforcementFailureAudited(t *testing.T) {
	led := &recLedger{}
	enf := quarantine.WithMover("/quarantine", &fakeMover{err: errors.New("disk full")})
	e := engineWith(led, corev1.Action_ACTION_QUARANTINE_LOCAL, enf)

	if _, err := e.Process(context.Background(), fsEvent("e1", "/home/alice/leak.csv")); err != nil {
		t.Fatal(err)
	}
	if len(led.entries) != 2 {
		t.Fatalf("entries = %d, want 2 (decision + failed enforcement)", len(led.entries))
	}
	if led.entries[1].OutcomeKind != "enforcement-failed" {
		t.Errorf("failed enforcement not audited: %q — a failed enforcement is not silence (D14)", led.entries[1].OutcomeKind)
	}
	if led.entries[1].OutcomeStage == "" {
		t.Error("enforcement-failed entry carries no reason")
	}
}

// The real filesystem mover moves a real file into the quarantine dir.
func TestQuarantineMovesFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "leak.csv")
	if err := os.WriteFile(src, []byte("111.444.777-35"), 0o600); err != nil {
		t.Fatal(err)
	}
	qdir := filepath.Join(dir, "quarantine")
	enf := quarantine.New(qdir)

	if err := enf.EnforceTarget(context.Background(), &corev1.Decision{Action: corev1.Action_ACTION_QUARANTINE_LOCAL}, src); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("the flagged file is still at its original path — it was not moved")
	}
	moved := filepath.Join(qdir, "leak.csv")
	if _, err := os.Stat(moved); err != nil {
		t.Errorf("the file was not moved to quarantine: %v", err)
	}
	info, _ := os.Stat(qdir)
	if info.Mode().Perm() != 0o700 {
		t.Errorf("quarantine dir mode = %v, want 0700 (owner-only)", info.Mode().Perm())
	}
	// Enforce without a target refuses rather than silently no-oping.
	if err := enf.Enforce(context.Background(), &corev1.Decision{}); err == nil {
		t.Error("Enforce with no target should refuse, not silently succeed")
	}
}
