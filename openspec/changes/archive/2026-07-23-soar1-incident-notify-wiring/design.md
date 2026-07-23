## Context

`MaterializeIncidents` (`internal/controlplane/incidents.go`) upserts each correlated incident:

```sql
INSERT INTO incidents (...) VALUES (...)
ON CONFLICT (subject_id) WHERE state = 'open'
DO UPDATE SET alert_count = EXCLUDED.alert_count, ... , updated_at = now()
```

The async notification path already exists and is proven: `emit` (SIEM-12) stamps a deterministic id,
checks the in-memory `dedupeSet`, checks the durable `notify_dedupe` table (R34-13, fail-open), then
queues onto `notifyQ`; `deliverLoop` delivers off the ingest path. `emit` is a no-op unless
`SetNotifier` has started the loop (`notifyRunning`). The gap is only the wiring: incident creation
never calls `emit`.

## Goals / Non-Goals

**Goals:**
- Materializing a **new** incident delivers exactly one notification.
- Re-materializing the **same** open incident (the extend-the-burst UPDATE) delivers none.
- Dedup is **per-incident**: a fresh incident for the same subject (after the first is acked/closed)
  pages again — so the idempotency key is the incident id, not the content-window key.
- Reuse the existing best-effort, off-ingest delivery and its two-tier idempotency unchanged.

**Non-Goals:**
- No scheduled/ticker materialization (SOAR-2), no state machine beyond the existing
  open→acknowledged, no actuation or intent verbs (ADR-12 Tier-2/3), no notification routing (SOAR-9).
- No proto change, no migration.

## Decisions

1. **Insert-vs-update is decided in SQL, per incident, via `RETURNING (xmax = 0) AS inserted`.**
   Postgres sets `xmax = 0` on a freshly-inserted row and non-zero on a row touched by the `DO UPDATE`
   path. Switching `pool.Exec` to `pool.Query`/`QueryRow` with `RETURNING id, (xmax = 0) AS inserted`
   tells us, authoritatively and race-free within the statement, whether THIS materialization created
   the incident. Only `inserted = true` emits. This is the correctness core; the mutation that always
   emits (ignoring `inserted`) must fail the re-materialize-zero test.

2. **The notification id is derived from the incident id, not `notifyID`.** `emit` only computes the
   content-window `notifyID` when `Notification.ID == ""`. SOAR-1 sets `ID = "inc_" + <incident id>`
   explicitly, so:
   - the same incident id can never page twice (durable `notify_dedupe` keyed on `inc_<id>`), even
     across a restart or a redundant materialize;
   - a *different* incident (new autoincrement id) for the same subject after the first is
     acked/closed gets a different key and pages again — which the content-window key would wrongly
     suppress inside a 10-minute window.
   The mutation that drops the explicit id (falling back to `notifyID`) must fail the
   distinct-second-incident-pages-again test.

3. **New `KindIncident notify.Kind = "incident"`** in `internal/notify/notify.go`. It is a string
   const, so no proto and no wire-format change. The notification carries `Subject`, `RiskScore`
   (peak risk), and a `Detail` summarizing severity + alert count + host count — pseudonymous, no
   content, consistent with `KindPeerAlert`.

4. **Emit is best-effort and off-ingest, unchanged.** `MaterializeIncidents` calls `s.emit(ctx, n)`
   after each successful insert; `emit` returns immediately (no-op if no sink). A delivery failure is
   already counted/logged by `deliverLoop`, never propagated — so notification never fails
   materialization. The `incidents` row is the record; the page is an additive copy (D30).

## Risks / Trade-offs

- **Emitting inside the per-incident loop vs. after the loop:** we emit per insert as we go, so a
  mid-loop error still delivers pages for the incidents already inserted (they are persisted). This
  matches "the row is the record; the page is additive" — no all-or-nothing coupling.
- **`xmax` reuse subtlety:** `xmax = 0` is the documented insert marker; a concurrent locker could in
  theory set `xmax` on a freshly inserted row, but `MaterializeIncidents` inserts and reads in one
  statement under one subject key, so the value reflects this statement's action. Acceptable for a
  best-effort page; a false "updated" would at worst miss one page (never double-page).
- **Fail-open dedup:** during a DB outage the durable check fails open and may double-page — an
  accepted trade (a missed page is worse than a rare duplicate), already the SIEM-12/R34-13 policy.
