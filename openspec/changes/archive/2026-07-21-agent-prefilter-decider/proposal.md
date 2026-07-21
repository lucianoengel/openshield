## Why

D94 shipped the two-tier prefilter's DECISION logic behind a `PartialDecider` seam but
left the seam's implementation out of scope. This provides it: the concrete synchronous
tier that reads a bounded prefix, classifies it in the sandboxed worker, runs the same
OPA policy the async engine runs, and returns a Decision — making tier-1 real and testable
end to end with a live worker, everything except the kernel permission syscall (D52).

## What Changes

- `prefilter.Decider` (implements `prefilter.PartialDecider`, `NewDecider`): reads a
  bounded prefix of the event target (double-bounded — a read `LimitReader` for
  IPC/memory and the worker's `MaxBytes` for the parse), classifies it via the worker
  (D72 — content parsed in the worker, never here), runs the policy through an
  audit-LESS dispatcher, and returns the Decision.

## Capabilities

### Modified Capabilities
- `inline-prevention`: the prefilter's PartialDecider is now concrete — a bounded
  classify + policy that yields the synchronous verdict from a real worker.

## Impact

- New `internal/agent/prefilter/decider.go`; `docs/decisions.md` D95.
- Proven with a REAL worker binary + real OPA policy (no Postgres — the synchronous tier
  writes no ledger): a bounded prefix with a CPF → parsed in the worker → BLOCK at high
  confidence → and, wired through the PreFilter + the REAL watchdog, an inline kernel
  DENY (a legitimate open prevented) while the async job is still submitted; a clean file
  → ALLOW; a CPF PAST the prefix → ALLOW (the bound is real, deferred to async); an empty
  path → its own error.
- NOT in scope (unchanged from D94): the privileged permission-mode syscall + fd-passing
  (B2, external-gated, D52); a distinct DENY_OPEN verb. Respects D13 (never parses — the
  worker does), D16 (no audit in the sync tier; the async engine owns the durable record),
  D17 (a read/parse failure surfaces, becoming the prefilter's fail-open).
