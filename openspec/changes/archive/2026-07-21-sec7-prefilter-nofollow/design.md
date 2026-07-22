## Context

The enforcers read a flagged file via safeio (O_NOFOLLOW + regular-only, D65). The prefilter
read the same kind of target with a plain os.Open — the same TOCTOU the enforcers closed, left
open on the read path.

## Goals / Non-Goals

**Goals:** the prefilter prefix read gets the safeio TOCTOU guarantees, bounded.

**Non-Goals:** parent-component openat2; fd-passing from the producer.

## Decisions

**An opener, not just a reader.** `ReadRegularNoFollow` reads the WHOLE file; the prefilter
wants only a prefix. Refactored into `OpenRegularNoFollow` (same O_NOFOLLOW + fstat-regular
guarantees, returns the open file) so the prefilter reads a bounded prefix off the validated
handle. `ReadRegularNoFollow` now delegates to it — no behaviour change for the enforcers.

## Risks / Trade-offs

- **Only the final component is guarded** (the documented safeio residual). The parent-swap
  and fd-passing hardenings remain follow-ups, tied to the permission-mode agent (Phase B).
