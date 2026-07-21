// Package watchdog owns the fanotify permission answer.
//
// This is the riskiest contract in the system (D3/D17/D18). A process that
// triggers a FAN_OPEN_PERM event blocks in TASK_UNINTERRUPTIBLE — SIGKILL will
// not free it — until the agent writes a response. A responder that is slow,
// deadlocked, or waiting on an unbounded evaluation therefore hangs the process
// and, on a busy path, the machine.
//
// The watchdog guarantees the kernel is answered within a hard deadline no
// matter what evaluation does. It is DELIBERATELY separate from the dispatcher's
// StageDeadline: that bounds the dispatcher's in-process wait, but Go cannot
// preempt a stage goroutine, so a hung pipeline still owes the kernel an answer.
// The watchdog is that answer.
//
// The kernel edge (reading events, writing the fanotify_response) is a thin
// adapter behind Responder, so all of the logic that separates a safe fail-open
// from a hung host is tested in ordinary Go without CAP_SYS_ADMIN.
package watchdog

import (
	"context"
	"fmt"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
)

// PermissionEvent is one decoded FAN_OPEN_PERM event.
type PermissionEvent struct {
	PID  int32
	FD   int32  // kernel fd for the accessed file; -1 in tests
	Path string // best-effort, for audit only
}

// Verdict is what evaluation decided. Phase 1 only ever produces Allow; the
// Block path exists so the mechanism is complete for Phase 2 enforcement.
type Verdict int

const (
	VerdictAllow Verdict = iota
	VerdictBlock
)

// Responder writes the kernel answer. The production implementation writes a
// fanotify_response to the fanotify fd; the test implementation records it.
type Responder interface {
	Allow(e PermissionEvent) error
	Deny(e PermissionEvent) error
}

// Evaluator decides an event's verdict. In production this drives the pipeline;
// it is an interface so the watchdog logic is testable in isolation.
type Evaluator interface {
	Evaluate(ctx context.Context, e PermissionEvent) (Verdict, error)
}

// AuditFunc records a terminal event. It carries the core severity vocabulary so
// a fail-open is recorded exactly as loudly as the dispatcher records a timeout.
// It returns an error, which surfaces — a failed audit append is never silent —
// but never retracts an answer already given to the kernel.
type AuditFunc func(ctx context.Context, e PermissionEvent, severity core.Severity, reason string) error

// Watchdog answers permission events under a hard budget.
type Watchdog struct {
	SelfPID   int32
	Budget    time.Duration
	Responder Responder
	Evaluator Evaluator
	Audit     AuditFunc
}

// Handle answers exactly one permission event. It returns an error only for an
// audit-append failure (which the caller must see); the kernel is always
// answered, and answered exactly once, before any such error can be returned.
func (w *Watchdog) Handle(ctx context.Context, e PermissionEvent) error {
	// Self-access is allowed by IDENTITY, before any evaluation. The agent reads
	// policy and writes the ledger; waiting on its own access would deadlock it
	// against itself, unrecoverably (the block is uninterruptible).
	if e.PID == w.SelfPID {
		return w.Responder.Allow(e)
	}

	type result struct {
		v   Verdict
		err error
	}
	// Buffered so an abandoned evaluation goroutine can still send and exit
	// rather than blocking forever after we have already answered on timeout.
	done := make(chan result, 1)

	evalCtx, cancel := context.WithTimeout(ctx, w.Budget)
	defer cancel()
	go func() {
		v, err := w.Evaluator.Evaluate(evalCtx, e)
		done <- result{v, err}
	}()

	select {
	case r := <-done:
		// An evaluation ERROR is not a reason to block: erroring closed would
		// hang the host on a classifier crash. It is a fail-open too, audited.
		if r.err != nil {
			return w.failOpen(ctx, e, fmt.Sprintf("fail-open: evaluation error: %v", r.err))
		}
		if r.v == VerdictBlock {
			// Phase 1 never reaches here; the mechanism is complete for Phase 2.
			return w.Responder.Deny(e)
		}
		return w.Responder.Allow(e)
	case <-evalCtx.Done():
		// The budget elapsed first. Answer NOW and let the abandoned goroutine
		// finish and be discarded — the kernel already has its answer, and
		// answering twice is a protocol error.
		return w.failOpen(ctx, e, "fail-open: evaluation exceeded the per-event budget")
	}
}

// failOpen writes the allow FIRST, then audits. The order is load-bearing: the
// ledger write must never sit inside the permission window it records, or a slow
// ledger becomes a hung host. The audit failure surfaces but cannot retract the
// allow already given.
func (w *Watchdog) failOpen(ctx context.Context, e PermissionEvent, reason string) error {
	if err := w.Responder.Allow(e); err != nil {
		return err
	}
	if w.Audit == nil {
		return nil
	}
	if err := w.Audit(ctx, e, core.SeverityHigh, reason); err != nil {
		return fmt.Errorf("watchdog: allowed (fail-open) but audit failed: %w", err)
	}
	return nil
}
