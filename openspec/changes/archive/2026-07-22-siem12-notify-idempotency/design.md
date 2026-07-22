## Context

`emit` (SIEM-8/-11) enqueues a notification for async delivery and stamped `n.ID = newNotifyID()` — a
random value per call. `Notification.ID` is documented as a stable idempotency key, but a random
per-emit value is stable only within a single delivery's retries, not across a re-detection of the
same logical alert. The upstream peer-alert path already has a per-subject cooldown, but a client
timeout after a server success (the client retries the same telemetry) still re-detects and re-emits,
and there was no server-side dedup, so it double-paged.

## Goals / Non-Goals

**Goals:**
- A deterministic idempotency id: the same logical alert → the same id within a time window.
- Server-side suppression of a duplicate id, bounded in memory, counted not silent.
- No change to delivery semantics (best-effort, off-ingest, transient-retry / permanent-no-retry).

**Non-Goals:**
- Cross-restart idempotency (the seen-set is in-memory; a restart may re-page once — acceptable, a
  page is not the record). Persisting it is out of scope.
- Changing the upstream detection cooldowns.

## Decisions

### D-a · Deterministic id = hash(kind | subject | agentID | window-bucket)
`notifyID(n)` truncates `n.At` to `notifyDedupeWindow` (10 min) and hashes
`kind|subject|agentID|bucket` (SHA-256, 12-byte hex, `ntf_` prefix). Truncating the timestamp is what
makes two re-detections seconds apart share an id while a new occurrence in a later window gets a new
one. A caller that pre-set `ID` keeps it.

*Alternative considered:* hash the whole notification including `At` at full resolution. **Rejected** —
two re-detections are milliseconds/seconds apart, so a full-resolution timestamp defeats the dedup.
The window bucket is the point.

### D-b · Bounded FIFO seen-set, checked atomically in emit
`dedupeSet` holds a `map[string]struct{}` + an insertion-ordered slice; `markNew` is an atomic
check-and-record under a mutex, evicting the oldest id past a capacity cap (4096). `emit` calls
`markNew(n.ID)`; a `false` result (already seen) suppresses delivery and increments `NotifyDeduped`.
Marking before the enqueue keeps the check race-free; the rare mark-then-queue-full case is acceptable
(queue-full is already a counted drop, and a page is not the record).

*Alternative considered:* an unbounded set, or dedup in `deliverLoop`. **Rejected** — unbounded grows
without limit; checking in `emit` suppresses the duplicate before it consumes a queue slot.

### D-c · Observability
`NotifyDeduped` is exposed as `openshield_notify_deduped_total`, beside the existing failures/dropped
counters — a suppression is observable (D28), not silent.

## Risks / Trade-offs

- **Window-boundary straddle** → two re-detections that fall either side of a 10-min boundary get
  different ids and both page. Rare and self-correcting (still one extra page at worst); the window is
  a tunable constant if it ever matters.
- **In-memory seen-set lost on restart** → a re-detection immediately after a restart may page once
  more. Acceptable — bounded, and the alert record is unaffected.
- **Determinism/replay** → unrelated to policy replay; the id is a pure function of the alert, so it is
  itself deterministic.

## Open Questions

None.
