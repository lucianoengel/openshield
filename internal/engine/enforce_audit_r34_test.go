package engine_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/quarantine"
)

// failLedger fails every Append — to prove the engine does not SILENTLY drop an
// enforcement-audit append (R34-7).
type failLedger struct{}

func (failLedger) Append(context.Context, *core.Entry) error { return errors.New("ledger down") }
func (failLedger) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{}, nil
}
func (failLedger) Close() error { return nil }

// TestEnforcementAuditFailureIsCountedNotDropped (R34-7): when the enforcement-audit
// append fails, the engine counts it (EnforceAuditDropped) rather than swallowing
// the error — a dropped append for an automated action must be observable.
func TestEnforcementAuditFailureIsCountedNotDropped(t *testing.T) {
	mover := &fakeMover{}
	enf := quarantine.WithMover("/quarantine", mover)
	e := engineWith(failLedger{}, corev1.Action_ACTION_QUARANTINE_LOCAL, enf)

	if _, err := e.Process(context.Background(), fsEvent("e1", filepath.Join(t.TempDir(), "leak.csv"))); err != nil {
		// A dispatch/audit error on the decision path is fine; we only care that the
		// enforcement-audit drop was counted.
		_ = err
	}
	if got := e.EnforceAuditDropped(); got < 1 {
		t.Fatalf("EnforceAuditDropped = %d, want ≥1 — a failed enforcement-audit append must be counted, not silently dropped (R34-7)", got)
	}
}
