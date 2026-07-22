## Context

`peerueba.Analyzer` keeps `map[subject]*entry{count float64, last time.Time}`, a decaying
leave-one-out peer baseline (D61). `ContextFor` decays each entry forward to `now()` before
computing a z-score, so the stored pair `{count, last}` is a complete, time-independent
representation — nothing else is needed to resume. The control plane already persists a
SEC-10 version base (migration 014) and reserves a fresh monotonic version block per startup,
so context-version uniqueness across restarts is already handled and is NOT part of this change.

## Goals / Non-Goals

**Goals:**
- Survive a restart with an EXACT baseline: a restored analyzer computes identical risk.
- Best-effort persistence that never blocks or breaks ingest/enable.

**Non-Goals:**
- Broadening the analyzer's features (per-kind rate, time-of-day, data volume) — the L half
  of SIEM-5, deferred; no new detector signal here.
- Persisting the context-version counter (already handled by the SEC-10 version base).
- Guaranteed/synchronous persistence on every observe (too hot; periodic + shutdown is enough
  — a lost few-minutes tail only shortens the post-restart warmth slightly, not correctness).

## Decisions

- **Snapshot is `{count, last}` per subject, restored verbatim.** Because decay is forward from
  `last`, re-inserting the stored pair reproduces the exact decayed value at any later query
  time. `Snapshot()` takes the lock and copies; `WithSnapshot` seeds the map in `New`. No decay
  is applied at snapshot or restore time — that would double-apply decay against the query-time
  computation.
- **UPSERT keyed on subject.** `PersistBaselines` writes each snapshot row with
  `ON CONFLICT (subject) DO UPDATE`, so re-persisting a warm fleet is idempotent and cheap.
  Subjects are bounded (pseudonymous users), so a full snapshot per interval is fine.
- **Load on enable, best-effort.** `EnablePeerUEBA` calls `loadBaselines`; on error it logs and
  starts cold (an analytics warmup gap is far better than failing to enable detection). Load
  happens before the analyzer starts observing, so no race with the ingest stream.
- **Version base stays independent.** `EnablePeerUEBA` still reserves a fresh version block;
  restoring baselines does not restore or collide the version counter (SEC-10 unchanged).

## Risks / Trade-offs

- **A crash loses the tail since the last persist** → periodic (5m) + shutdown persist bounds
  it; the lost tail only slightly shortens post-restart baseline warmth, never corrupts it.
- **Clock skew across restarts affects decay** → the same risk the live analyzer already has
  (it trusts the wall clock for decay); persistence stores real timestamps, no new exposure.
- **Snapshot under lock briefly pauses Observe** → the map is small (bounded subjects) and the
  copy is O(n) of a fleet's user count; negligible.
