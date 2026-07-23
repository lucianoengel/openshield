## Context

`emit` (D172/SIEM-12) stamps a deterministic id (`notifyID` = hash of kind|subject|agent|window-bucket)
and checks a bounded in-memory `dedupeSet.markNew(id)` before enqueuing, so a re-detected alert pages
once. The set is process-local, so a restart forgets it and the same alert re-detected in the same
window pages again. `peer_alerts.dedup_key` already exists (ADR-10) but is a CORRELATION key on the
recorded alert, not a delivery-idempotency ledger — a separate concern.

## Goals / Non-Goals

**Goals:**
- The "page exactly once" guarantee survives a restart/failover for the dedup window.
- Never MISS a page because the durable layer is unavailable (fail-open).
- Keep the fast path fast (no DB hit for an obvious same-process duplicate).
- Bounded storage (prune aged ids).

**Non-Goals:**
- Cross-CLUSTER dedup beyond what one shared Postgres gives (the DB is the shared authority; two servers
  on the same DB already dedupe against each other, which is the failover case).
- Changing the id derivation or the window (unchanged from D172).
- Deduping at the receiver (the id is already delivered so a receiver CAN dedupe; that is its choice).

## Decisions

1. **A dedicated `notify_dedupe(id PK, emitted_at)` table**, not reuse of `peer_alerts.dedup_key`:
   delivery-idempotency is a different lifecycle from an alert record (overdue-agent notifications have
   no peer_alerts row at all; a suppressed re-detection must not write an alert row). One small table
   keyed by the notification id is the clean model.

2. **`INSERT ... ON CONFLICT (id) DO NOTHING`, RowsAffected==1 means new.** Atomic check-and-record in
   one statement — no read-then-write race between two servers or two goroutines. `emitted_at` is set
   for pruning only.

3. **Order: in-memory pre-check THEN durable.** The in-memory `markNew` runs first (fast, no DB); only
   if it says "new" does `emit` do the durable insert. A same-process duplicate never touches the DB; a
   post-restart duplicate is caught by the DB (in-memory says new, DB conflict says duplicate).

4. **Fail-open.** `markNotifyDurable` returns `(true, nil)` when `s.pool == nil` (a pool-less test
   Server, or an intentionally DB-less deployment). On a DB ERROR it returns the error and `emit` logs
   it and PROCEEDS to enqueue — a double-page during a DB outage is acceptable; a missed page is not.
   The insert uses a fresh short-timeout context so a slow/cancelled caller ctx cannot wedge delivery.

5. **Prune on the leader retention loop.** `PruneNotifyDedupe(before)` deletes ids older than a few
   dedup windows; the server already runs a retention timer under the leader, so the prune rides it. An
   id only needs to outlive its window for the guarantee to hold.

## Risks / Trade-offs

- **A DB write per emitted alert.** Emit fires only when an alert crosses the threshold (peer-UEBA is
  cooldown-throttled; overdue is per-silence-edge), so this is per-ALERT, not per-event — low frequency.
  Acceptable for the durability it buys.
- **Fail-open means a DB outage can double-page.** Deliberate: availability of the page beats strict
  idempotency during an outage. Documented, logged (so the operator knows the durable layer was down).
- **Two servers sharing a DB dedupe against each other** — which is exactly right for active-passive
  failover (the new leader will not re-page what the old one delivered), and harmless for a single
  server.
