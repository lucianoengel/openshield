package watchdog_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
	"github.com/lucianoengel/openshield/internal/core"
)

// recordingResponder records every kernel answer, so a test can assert exactly
// one answer of the right kind per event.
type recordingResponder struct {
	mu      sync.Mutex
	allows  int
	denies  int
	answers int
}

func (r *recordingResponder) Allow(watchdog.PermissionEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allows++
	r.answers++
	return nil
}
func (r *recordingResponder) Deny(watchdog.PermissionEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.denies++
	r.answers++
	return nil
}
func (r *recordingResponder) counts() (allows, denies, answers int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.allows, r.denies, r.answers
}

type evalFunc func(ctx context.Context, e watchdog.PermissionEvent) (watchdog.Verdict, error)

func (f evalFunc) Evaluate(ctx context.Context, e watchdog.PermissionEvent) (watchdog.Verdict, error) {
	return f(ctx, e)
}

type auditRecord struct {
	severity core.Severity
	reason   string
}

func newWatchdog(r watchdog.Responder, ev watchdog.Evaluator, budget time.Duration, audit watchdog.AuditFunc) *watchdog.Watchdog {
	return &watchdog.Watchdog{
		SelfPID: 1, Budget: budget, Responder: r, Evaluator: ev, Audit: audit,
	}
}

// Task 3.1 — a slow evaluation still yields a timely allow. If the responder
// waited on evaluation, this test would exceed its own deadline.
func TestSlowEvalFailsOpenInTime(t *testing.T) {
	r := &recordingResponder{}
	slow := evalFunc(func(ctx context.Context, _ watchdog.PermissionEvent) (watchdog.Verdict, error) {
		<-ctx.Done() // never returns before the budget
		return watchdog.VerdictAllow, ctx.Err()
	})
	w := newWatchdog(r, slow, 50*time.Millisecond, nil)

	start := time.Now()
	if err := w.Handle(context.Background(), watchdog.PermissionEvent{PID: 99}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("answer took %v — the responder waited on evaluation instead of the budget", elapsed)
	}
	if allows, _, answers := r.counts(); allows != 1 || answers != 1 {
		t.Errorf("allows=%d answers=%d, want 1 and 1 (fail-open)", allows, answers)
	}
}

// Task 3.2 — exactly one answer even when the result lands after the timeout.
func TestNoDoubleAnswer(t *testing.T) {
	r := &recordingResponder{}
	released := make(chan struct{})
	late := evalFunc(func(ctx context.Context, _ watchdog.PermissionEvent) (watchdog.Verdict, error) {
		<-released // return only after the test says so — well after the budget
		return watchdog.VerdictBlock, nil
	})
	w := newWatchdog(r, late, 30*time.Millisecond, nil)

	if err := w.Handle(context.Background(), watchdog.PermissionEvent{PID: 99}); err != nil {
		t.Fatal(err)
	}
	// Now let the abandoned goroutine finish; it must not produce a second answer.
	close(released)
	time.Sleep(50 * time.Millisecond)

	if _, denies, answers := r.counts(); answers != 1 || denies != 0 {
		t.Errorf("answers=%d denies=%d, want exactly 1 allow — a late result answered twice", answers, denies)
	}
}

// Task 3.3 — a fail-open is audited high-severity and is distinguishable.
func TestFailOpenIsAuditedHighSeverity(t *testing.T) {
	r := &recordingResponder{}
	var got auditRecord
	var audited atomic.Bool
	audit := func(_ context.Context, _ watchdog.PermissionEvent, sev core.Severity, reason string) error {
		got = auditRecord{sev, reason}
		audited.Store(true)
		return nil
	}
	slow := evalFunc(func(ctx context.Context, _ watchdog.PermissionEvent) (watchdog.Verdict, error) {
		<-ctx.Done()
		return watchdog.VerdictAllow, ctx.Err()
	})
	w := newWatchdog(r, slow, 20*time.Millisecond, audit)

	if err := w.Handle(context.Background(), watchdog.PermissionEvent{PID: 99}); err != nil {
		t.Fatal(err)
	}
	if !audited.Load() {
		t.Fatal("fail-open produced no audit event — a silent fail-open is the worst failure")
	}
	if got.severity != core.SeverityHigh {
		t.Errorf("severity = %v, want high — a fail-open must be as loud as a timeout", got.severity)
	}
	if got.reason == "" {
		t.Error("fail-open audit has no reason identifying it")
	}
}

// Task 3.4 — self-PID is allowed without the evaluator ever running.
func TestSelfPIDBypassesEvaluation(t *testing.T) {
	r := &recordingResponder{}
	var evaluated atomic.Bool
	ev := evalFunc(func(context.Context, watchdog.PermissionEvent) (watchdog.Verdict, error) {
		evaluated.Store(true)
		return watchdog.VerdictAllow, nil
	})
	w := newWatchdog(r, ev, time.Second, nil)

	if err := w.Handle(context.Background(), watchdog.PermissionEvent{PID: w.SelfPID}); err != nil {
		t.Fatal(err)
	}
	if evaluated.Load() {
		t.Error("the evaluator ran for a self-PID event — the agent would deadlock on its own access")
	}
	if allows, _, _ := r.counts(); allows != 1 {
		t.Errorf("self-PID event was not allowed (allows=%d)", allows)
	}
}

// Task 3.5 — a "bomb" (slow) evaluation hits the budget rather than hanging, and
// is audited. Same shape as 3.1 but framed as the budget guarantee.
func TestBudgetCeilingNotHang(t *testing.T) {
	r := &recordingResponder{}
	var audited atomic.Bool
	audit := func(context.Context, watchdog.PermissionEvent, core.Severity, string) error {
		audited.Store(true)
		return nil
	}
	bomb := evalFunc(func(ctx context.Context, _ watchdog.PermissionEvent) (watchdog.Verdict, error) {
		// Simulate a decompression bomb: burn well past the budget.
		select {
		case <-time.After(10 * time.Second):
		case <-ctx.Done():
		}
		return watchdog.VerdictAllow, ctx.Err()
	})
	w := newWatchdog(r, bomb, 40*time.Millisecond, audit)

	done := make(chan error, 1)
	go func() { done <- w.Handle(context.Background(), watchdog.PermissionEvent{PID: 99}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Handle did not return — a bomb hung the responder instead of hitting the budget")
	}
	if !audited.Load() {
		t.Error("budget-exceed fail-open was not audited")
	}
}

// Task 3.6 — a failed audit append surfaces, but the allow still happened.
func TestAuditFailureDoesNotRetractAllow(t *testing.T) {
	r := &recordingResponder{}
	audit := func(context.Context, watchdog.PermissionEvent, core.Severity, string) error {
		return errors.New("ledger down")
	}
	slow := evalFunc(func(ctx context.Context, _ watchdog.PermissionEvent) (watchdog.Verdict, error) {
		<-ctx.Done()
		return watchdog.VerdictAllow, ctx.Err()
	})
	w := newWatchdog(r, slow, 20*time.Millisecond, audit)

	err := w.Handle(context.Background(), watchdog.PermissionEvent{PID: 99})
	if err == nil {
		t.Fatal("a failed audit append was swallowed — it must surface")
	}
	if allows, _, answers := r.counts(); allows != 1 || answers != 1 {
		t.Errorf("allows=%d answers=%d — the kernel must still have been allowed despite the "+
			"audit failure; the answer precedes and cannot depend on the ledger", allows, answers)
	}
}

// A completed evaluation with a Block verdict denies (Phase 2 mechanism, present
// now so the path is exercised).
func TestBlockVerdictDenies(t *testing.T) {
	r := &recordingResponder{}
	block := evalFunc(func(context.Context, watchdog.PermissionEvent) (watchdog.Verdict, error) {
		return watchdog.VerdictBlock, nil
	})
	w := newWatchdog(r, block, time.Second, nil)
	if err := w.Handle(context.Background(), watchdog.PermissionEvent{PID: 99}); err != nil {
		t.Fatal(err)
	}
	if _, denies, answers := r.counts(); denies != 1 || answers != 1 {
		t.Errorf("denies=%d answers=%d, want 1 and 1", denies, answers)
	}
}
