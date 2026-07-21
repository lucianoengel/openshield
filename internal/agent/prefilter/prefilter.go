// Package prefilter is the synchronous tier of two-tier inline prevention (Phase B,
// closes D49).
//
// All enforcement today is POST-decision: the engine classifies a file fully, decides,
// records, then contains (quarantine/encrypt) — the file was already opened. That is
// containment, not prevention (D16). True prevention means answering the fanotify
// PERMISSION event (FAN_OPEN_PERM) with DENY before the open completes — but the process
// blocks uninterruptibly in that window (D18), so a full parse cannot run inside it.
//
// The two-tier answer: a CHEAP synchronous tier decides within the permission budget,
// while the FULL classification runs asynchronously for audit + containment. This
// package is the synchronous tier. It is a watchdog.Evaluator (D18 owns the budget,
// self-PID exemption, and fail-open — this only decides), so a slow prefilter is still
// bounded and fail-opened by the watchdog; the prefilter's job is to be cheap enough to
// usually answer with a REAL verdict, and to be safe when it cannot.
//
// It does NOT parse content itself — the privileged agent must never parse attacker
// bytes (D13). The partial classification runs in the sandboxed worker (D72) behind the
// PartialDecider seam; the async full job runs in the unprivileged engine. This package
// holds only the timing/decision logic, wired behind those seams and behind the
// watchdog's Evaluator interface.
package prefilter

import (
	"context"
	"log/slog"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// PartialDecider produces a Decision from a CHEAP, BOUNDED classification of an event's
// target — only a size-limited prefix is parsed, in the sandboxed worker (D13/D72), so
// the synchronous answer fits the permission budget. It runs the SAME classify→policy
// machinery as the async engine, just on a prefix and WITHOUT an audit write (the async
// tier owns the durable record). A read/parse failure is an error, never a silent clean
// verdict (D17).
type PartialDecider interface {
	DecidePartial(ctx context.Context, e watchdog.PermissionEvent) (*corev1.Decision, error)
}

// AsyncSubmitter hands the full event to the asynchronous tier — the engine that fully
// classifies the whole file, writes the durable audit row, and contains it (D16). Submit
// MUST NOT block the permission window: it enqueues and returns.
type AsyncSubmitter interface {
	Submit(e watchdog.PermissionEvent)
}

// PreFilter is the synchronous tier. It implements watchdog.Evaluator.
type PreFilter struct {
	decide  PartialDecider
	async   AsyncSubmitter
	minConf float64
	logger  *slog.Logger
}

// New builds the prefilter. minConf is the confidence FLOOR for an inline block: a
// partial decision below it does NOT block inline (see Evaluate). A minConf ≤ 0 is
// raised to a conservative default — inline prevention must never block on an
// unqualified guess, so "block on any confidence" is not an accepted configuration.
func New(decide PartialDecider, async AsyncSubmitter, minConf float64, logger *slog.Logger) *PreFilter {
	if minConf <= 0 {
		minConf = DefaultMinConfidence
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &PreFilter{decide: decide, async: async, minConf: minConf, logger: logger}
}

// DefaultMinConfidence is the inline-block confidence floor when none is configured.
// High on purpose: an inline DENY hangs then fails an open, so it must be reserved for
// cheaply-provable, high-confidence hits — everything else is contained async instead.
const DefaultMinConfidence = 0.9

// Evaluate answers one permission event under the two-tier contract.
//
// Tier 2 (async) ALWAYS runs: the full-file job is submitted regardless of the
// synchronous verdict, so inline prevention NEVER replaces the complete classification,
// the durable audit row, or containment (D1/D16). Even a synchronous ALLOW is fully
// classified async; even a synchronous BLOCK still earns its durable record from the
// async tier.
//
// Tier 1 (synchronous) then decides within the permission window:
//   - a partial-decide ERROR fails OPEN (VerdictAllow + the error): erroring closed
//     would hang the host on a classifier crash (D17); the watchdog audits the error.
//   - an inline BLOCK is produced ONLY for a high-confidence deny (action BLOCK AND
//     confidence ≥ minConf). This is B3: prevent what you can cheaply PROVE. A
//     low-confidence partial hit (a prefix guess) does NOT block inline — it allows the
//     open and lets the async tier fully classify and contain, so a 4 KB-prefix false
//     positive never denies a legitimate open.
//   - everything else ALLOWS.
func (p *PreFilter) Evaluate(ctx context.Context, e watchdog.PermissionEvent) (watchdog.Verdict, error) {
	if p.async != nil {
		p.async.Submit(e)
	}

	dec, err := p.decide.DecidePartial(ctx, e)
	if err != nil {
		// Fail open. The watchdog records the error loudly; the async tier still runs.
		return watchdog.VerdictAllow, err
	}
	if dec.GetAction() == corev1.Action_ACTION_BLOCK && dec.GetConfidence() >= p.minConf {
		p.logger.Warn("prefilter: inline BLOCK (high-confidence partial deny)",
			"pid", e.PID, "path", e.Path, "confidence", dec.GetConfidence(), "reason", dec.GetReason())
		return watchdog.VerdictBlock, nil
	}
	return watchdog.VerdictAllow, nil
}
