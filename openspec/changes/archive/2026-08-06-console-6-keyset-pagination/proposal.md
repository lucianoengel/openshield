# CONSOLE-6 · Keyset pagination

## Why

`GET /events` clamps at `maxSearchLimit = 1000` with **no cursor and no `has_more`**. Against 90-day
retention that is not a hunting surface: an analyst gets the top 1000 rows and has no way to reach row
1001, and — worse — **no way to know row 1001 exists.** A truncated result that looks complete is the
failure mode, not the truncation itself.

The ordering is already a usable cursor: `ORDER BY received_at DESC, id DESC` over `fleet_telemetry`. The
tuple `(received_at, id)` is unique and monotone, so a page boundary is expressible without offsets —
which matters because `OFFSET` against a live ingest stream skips and repeats rows as new ones arrive at
the head.

## What Changes

- `EventFilter` gains an opaque cursor; the query gains a `(received_at, id) < (…)` keyset predicate.
- The response reports whether more rows exist, and the cursor to continue from.
- The cursor is **opaque but not secret**, and carries **no authority** — see the inherited requirement.

## Impact

- Affected specs: `control-plane`.
- No proto change, no migration. `GET /events` without a cursor behaves as before.

## ⚠️ REQUIREMENT INHERITED FROM CONSOLE-1: A CURSOR MUST NEVER BE A BEARER OF AUTHORIZATION

A cursor that encodes a position and is honoured without re-deriving the caller's authority lets one
operator replay another's cursor and page through rows they were never entitled to.

This is nearly free to prevent while the cursor is being designed and expensive once clients hold them.
The principal is already on the request context (D470), so authority is re-derived per page from the
credential — never read from the cursor. The cursor carries a POSITION and nothing else.

CONSOLE-1 deliberately did not build an inert scope field for this, and that stands: a constant that
always says "all" is unwired code by construction.

## Deliberately NOT in this increment

- **A stable snapshot across pages.** Rows arriving at the head while an analyst pages are not hidden;
  keyset pagination walks backwards from a fixed point, so new rows simply are not in the walk. A true
  snapshot needs a transaction or a watermark and is a separate decision.
- **Pagination on every surface.** `/events` is the one the hunt is built on and the one with a natural
  key. Extending it to `/alerts` and `/incidents` is mechanical once the shape is settled.
