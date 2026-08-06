# CONSOLE-6b · Keyset pagination for `/alerts`, `/search` and `/incidents`

## Why

CONSOLE-6 (D481) fixed `GET /events` and said, in its own "deliberately not in this increment" section,
that extending the walk to `/alerts` and `/incidents` was "mechanical once the shape is settled". The
three routes it left behind still carry the identical defect:

- `GET /alerts` clamps at whatever `limit` says (default 100), returns a **bare JSON array**, and says
  nothing about the rows it did not return.
- `GET /search` — the filtered alert hunt, the surface a SIEM UI is meant to query — clamps at
  `maxSearchLimit = 1000` with no cursor and no `has_more`.
- `GET /incidents` clamps the same way over the materialized incident list.

The failure is not the cap. It is that a capped result **looks complete**: an analyst reading the alert
queue concludes the fleet raised 1000 alerts, and an operator reading the incident list concludes there
are no incidents past the page. A wrong answer that looks authoritative, which is the D481 shape
relocated from one route to three.

The ordering on both tables is already a usable key. `peer_alerts` and `incidents` each have
`id BIGSERIAL PRIMARY KEY`, so `(detected_at, id)` and `(last_seen, id)` are unique and monotone —
exactly what `(received_at, id)` was for `/events`. **No migration and no new tiebreaker column is
required**; the general warning that a keyset walk over a non-unique `ORDER BY` silently skips rows
remains true and is pinned by a deliberate tie fixture rather than assumed away.

## What Changes

- Two sibling cursor types alongside `eventCursor`: `alertCursor{DetectedAt, ID}` (version tag `a1`) and
  `incidentCursor{LastSeen, ID}` (tag `i1`). `eventCursor` is untouched.
- **The version tag doubles as a namespace.** All three cursors encode the same shape, so without a
  discriminator an `/alerts` cursor presented to `/incidents` decodes successfully and serves a
  wrong-but-plausible page. This is not the authority requirement and must not be read as one: the tag
  says which walk a position belongs to, never who may walk it.
- `AlertFilter.Cursor`; `SearchPeerAlertsPage` becomes the paginated primitive and `SearchPeerAlerts`
  its `.Rows` wrapper (the `SearchTelemetry`/`SearchTelemetryPage` shape). `/alerts` and `/search` both
  route through it, so the two cannot disagree about what a page contains.
- `RecentIncidentsPage(ctx, limit, cursor)`; `RecentIncidents` becomes its `.Rows` wrapper.
- `/alerts`, `/search` and `/incidents` return `{rows, has_more, next_cursor?}` instead of a bare array.

## Impact

- Affected specs: `control-plane`.
- No proto change, **no migration**. Every route without a cursor still returns its first page.
- **Breaking response shape** on three routes (bare array → object), the same breaking-but-accepted
  change CONSOLE-6 already made for `/events`. There is no shipped console consuming them yet.
- No route mounting changes: only handler bodies inside `OperatorReadHandler()`'s mux, so the view-audit
  mount guard must still pass unmodified.

## ⚠️ THE CONSOLE-1 INHERITED REQUIREMENT CARRIES OVER UNCHANGED

A cursor carries a POSITION and nothing else. Authority is re-derived from the principal on the request
context on every page (D470), so a cursor lifted from another operator's session yields that operator's
position and the lifter's authority. The namespace tag added here is a *table* discriminator, not a scope
field, and encodes nothing about the caller.

## Deliberately NOT in this increment

- **`GET /incidents?rule=cross_domain`.** `CorrelateCrossDomain` is a live `GROUP BY entity_id` aggregate
  over a rolling window, recomputed per call. "The row after this one" is not defined across a
  re-aggregated `GROUP BY`, so a cursor there would be a position into a result set that no longer
  exists. A `cursor=` presented alongside `rule=cross_domain` is ignored, and that is stated in the code
  rather than left to look like an oversight.
- **A stable snapshot across pages** — ruled out by CONSOLE-6 for all keyset pagination here, and still
  out. See design.md for the `/incidents`-specific residual this leaves, which is real and documented.
- **A `(detected_at, id)` index on `peer_alerts`.** The table has no index on `detected_at` at all today,
  so a deep walk is a sort over a full scan with or without this change. Pre-existing, not introduced
  here; `/events` shipped without a composite index too. Flagged as a follow-up rather than silently
  matched.
- **A generic `Page[T]`.** There are no generics anywhere in `internal/`; introducing the first one as a
  side effect of extending pagination to three routes is a bigger structural decision than this ticket.
