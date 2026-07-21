package prefilter_test

import (
	"context"
	"errors"
	"testing"

	"github.com/lucianoengel/openshield/internal/agent/prefilter"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

type fakeDecider struct {
	dec *corev1.Decision
	err error
}

func (f fakeDecider) DecidePartial(context.Context, watchdog.PermissionEvent) (*corev1.Decision, error) {
	return f.dec, f.err
}

type recSubmitter struct{ got []watchdog.PermissionEvent }

func (r *recSubmitter) Submit(e watchdog.PermissionEvent) { r.got = append(r.got, e) }

func block(conf float64) *corev1.Decision {
	return &corev1.Decision{Action: corev1.Action_ACTION_BLOCK, Confidence: conf, Reason: "cpf in prefix"}
}
func allow() *corev1.Decision {
	return &corev1.Decision{Action: corev1.Action_ACTION_ALLOW, Confidence: 0.99}
}

func TestPreFilterInlineBlockOnHighConfidenceDeny(t *testing.T) {
	sub := &recSubmitter{}
	pf := prefilter.New(fakeDecider{dec: block(0.95)}, sub, 0.9, nil)

	v, err := pf.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 42, Path: "/data/secret.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if v != watchdog.VerdictBlock {
		t.Errorf("high-confidence partial deny = %v, want VerdictBlock (inline prevention, B3)", v)
	}
	// Tier 2 still ran — inline BLOCK never replaces the durable async record (D16).
	if len(sub.got) != 1 {
		t.Errorf("async submissions = %d, want 1 (the full-file job must run even on an inline block)", len(sub.got))
	}
}

func TestPreFilterLowConfidenceHitDoesNotBlockInline(t *testing.T) {
	sub := &recSubmitter{}
	// A BLOCK decision but BELOW the floor: a 4KB-prefix guess must not deny a real open.
	pf := prefilter.New(fakeDecider{dec: block(0.5)}, sub, 0.9, nil)

	v, err := pf.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 42, Path: "/data/x"})
	if err != nil {
		t.Fatal(err)
	}
	if v != watchdog.VerdictAllow {
		t.Errorf("low-confidence partial deny = %v, want VerdictAllow (contain async, don't block on a guess)", v)
	}
	if len(sub.got) != 1 {
		t.Errorf("async submissions = %d, want 1 (the async tier fully classifies + contains)", len(sub.got))
	}
}

func TestPreFilterAllowIsAllowed(t *testing.T) {
	sub := &recSubmitter{}
	pf := prefilter.New(fakeDecider{dec: allow()}, sub, 0.9, nil)
	v, err := pf.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 42})
	if err != nil || v != watchdog.VerdictAllow {
		t.Errorf("clean partial = (%v,%v), want (VerdictAllow,nil)", v, err)
	}
	if len(sub.got) != 1 {
		t.Errorf("async submissions = %d, want 1", len(sub.got))
	}
}

// A partial-decide error FAILS OPEN (VerdictAllow + the error, so the watchdog audits
// it) and the async tier still runs — erroring closed would hang the host (D17).
func TestPreFilterFailsOpenOnDecideError(t *testing.T) {
	sub := &recSubmitter{}
	pf := prefilter.New(fakeDecider{err: errors.New("worker crashed")}, sub, 0.9, nil)
	v, err := pf.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 42})
	if v != watchdog.VerdictAllow {
		t.Errorf("decide error = %v, want VerdictAllow (fail open, D17)", v)
	}
	if err == nil {
		t.Error("decide error swallowed — the watchdog must see it to audit the fail-open")
	}
	if len(sub.got) != 1 {
		t.Errorf("async submissions = %d, want 1 (async runs even when the sync tier errors)", len(sub.got))
	}
}

// The prefilter plugs into the REAL watchdog as its Evaluator: a high-confidence partial
// deny drives the kernel answer to Deny; the watchdog's budget/self-PID/fail-open still
// apply (this proves the seam, not just the logic in isolation).
func TestPreFilterDrivesWatchdogDeny(t *testing.T) {
	sub := &recSubmitter{}
	pf := prefilter.New(fakeDecider{dec: block(0.95)}, sub, 0.9, nil)
	resp := &recResponder{}
	wd := &watchdog.Watchdog{SelfPID: 1, Budget: 0, Responder: resp, Evaluator: pf}
	// Budget 0 would time out; give a real budget via a fresh watchdog.
	wd.Budget = 250_000_000 // 250ms

	if err := wd.Handle(context.Background(), watchdog.PermissionEvent{PID: 42, Path: "/data/secret"}); err != nil {
		t.Fatal(err)
	}
	if !resp.denied {
		t.Error("watchdog did not DENY on a high-confidence inline block — inline prevention did not reach the kernel answer")
	}
}

type recResponder struct{ allowed, denied bool }

func (r *recResponder) Allow(watchdog.PermissionEvent) error { r.allowed = true; return nil }
func (r *recResponder) Deny(watchdog.PermissionEvent) error  { r.denied = true; return nil }
