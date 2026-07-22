## Context

context_version (D27) records which analytics snapshot a Decision saw. An in-memory counter
that resets to 0 makes that ambiguous across restarts.

## Goals / Non-Goals

**Goals:** context_version monotonic + non-colliding across restarts.

**Non-Goals:** persisting notification dedup / cooldown / baselines (graceful-degradation
follow-ups).

## Decisions

**Reserve a block per startup, don't persist every bump.** Persisting the counter on every
Observe would be chatty. Instead each startup reserves a large monotonic BLOCK from a persisted
single-row counter (the ledger-sequence pattern, D66) and the analyzer counts within it. Two
runs sit in disjoint ranges, so no version string repeats — without a write per event.

**Best-effort, not fatal.** If the reservation fails (an old schema), the analyzer starts at 0
with a loud log — a cross-restart collision is worse than a within-run start, but neither is
fatal, and peer-UEBA is an opt-in analytics feature.

## Risks / Trade-offs

- **Block exhaustion:** a run emitting a billion version bumps would overrun into the next
  block. The block is sized (1e9) so a single run realistically never does; a larger block or a
  per-run UUID prefix is the escape hatch if needed.
- **Notification re-paging remains** until the dedup state is persisted (a noted follow-up).
