package gateway_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
)

// failingLedger fails every Append — to prove the GATEWAY does not silently drop an enforcement-audit
// append. The engine's identical path was fixed by R34-7; this one was still `_ = g.ledger.Append(...)`.
type failingLedger struct{ appends int }

func (l *failingLedger) Append(context.Context, *core.Entry) error {
	l.appends++
	return errors.New("ledger down")
}

func (*failingLedger) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{}, nil
}
func (*failingLedger) Close() error { return nil }

// blockAll advertises a block action and always succeeds, so the only thing that can fail on the
// enforcement path is the AUDIT of it.
type blockAll struct{}

func (blockAll) Capabilities() []corev1.Action { return []corev1.Action{corev1.Action_ACTION_BLOCK} }
func (blockAll) Enforce(context.Context, *corev1.Decision) error {
	return nil
}

// A FAILED ENFORCEMENT-AUDIT APPEND MUST BE OBSERVABLE.
//
// The action itself still happened — a flow was blocked — and only the evidence of it is missing. That is
// the worst shape for an automated action: the ledger is the product's claim, and a hole in it that
// nothing reports is indistinguishable from the action never having been taken.
//
// The gateway's sibling recordTunneled already logged its append failure; this path discarded it. Same
// file, two behaviours.
func TestAFailedEnforcementAuditIsCountedNotDropped(t *testing.T) {
	led := &failingLedger{}
	gw := gateway.New(&fakeWorker{}, deciding(corev1.Action_ACTION_BLOCK), led, nil, time.Second)
	gw.Enforcers = []core.Enforcer{blockAll{}}

	if _, err := gw.Process(context.Background(), req("f1", "payload")); err != nil {
		// The decision-path append fails too against this ledger; what matters here is the enforcement
		// audit specifically, asserted below.
		_ = err
	}

	if got := gw.EnforceAuditDropped(); got < 1 {
		t.Fatalf("EnforceAuditDropped = %d, want >=1 — a failed enforcement-audit append must be counted, "+
			"not swallowed by `_ = g.ledger.Append(...)`. The block still happened; only the evidence of "+
			"it is missing, and nothing said so.", got)
	}
}

// recordSuppression routes through the same function, so a kill-switch suppression whose audit fails is
// the case the comment on that function warns about in its own words: "a silent kill switch is
// indistinguishable from a product that has stopped working."
func TestASuppressedEnforcementWhoseAuditFailsIsAlsoCounted(t *testing.T) {
	led := &failingLedger{}
	gw := gateway.New(&fakeWorker{}, deciding(corev1.Action_ACTION_BLOCK), led, nil, time.Second)
	gw.Enforcers = []core.Enforcer{blockAll{}}

	ks := core.NewKillSwitch(nil)
	ks.Engage("integration test", "test")
	gw.KillSwitch = ks

	_, _ = gw.Process(context.Background(), req("f2", "payload"))

	if got := gw.EnforceAuditDropped(); got < 1 {
		t.Fatalf("EnforceAuditDropped = %d, want >=1 — the suppression record is what an operator asking "+
			"'what did we not block' reads, and its loss was silent", got)
	}
	// And the suppression itself is counted, which is the number D419 made reachable.
	if got := ks.Suppressions.Load(); got < 1 {
		t.Fatalf("Suppressions = %d, want >=1", got)
	}
}
