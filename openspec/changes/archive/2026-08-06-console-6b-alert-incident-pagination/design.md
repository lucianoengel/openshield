# Design — CONSOLE-6b

## Reuse the PATTERN, not the TYPE — and no schema change is needed

`peer_alerts` (migration 009) and `incidents` (018) both declare `id BIGSERIAL PRIMARY KEY`, unchanged
through 015/020/028/040/041/043/045. So `(detected_at, id)` and `(last_seen, id)` are already unique and
monotone, which is the entire property `(received_at, id)` supplied for `/events`. **The feared missing
tiebreaker does not exist on either table.**

What remains true, and is therefore tested rather than assumed, is the failure it warns about: a keyset
walk whose `ORDER BY` is not unique silently skips or repeats rows. Two alerts sharing a `detected_at` —
which the burst detector produces routinely, since it writes several alerts for one subject in one pass —
are ordered only by `id`. Drop `id` from the predicate and every row after the first tied one becomes
permanently unreachable in that walk. A fixture without a deliberate tie passes against that mutation,
so the tie is constructed on purpose.

Two sibling types are added; `eventCursor` is left alone:

    alertCursor{DetectedAt time.Time; ID int64}   // tag "a1"
    incidentCursor{LastSeen time.Time; ID int64}  // tag "i1"

REJECTED — retrofitting a shared `keysetCursor{Kind, At, ID}` for all three. Two reasons. **Blast
radius**: `/events` is shipped and load-bearing, and rewriting its codec to serve a feature it does not
need risks the one surface that proves the mechanism works. **In-flight compatibility**: changing
`/events`' wire format would 400 every cursor an analyst is mid-walk on — an unforced regression against
a shipped feature, to save three lines of struct.

## The version tag IS the namespace, and it is load-bearing

All three cursors encode an identical shape: a timestamp and an int64, colon-joined and base64url'd.
With no discriminator, an `/alerts` cursor (a `peer_alerts.id` position) presented to `/incidents`
**decodes successfully** and produces a page that is wrong but entirely plausible — the same
"looks complete but isn't" corruption D481 exists to prevent, relocated from row-count to row-identity.

So each type's version string doubles as its namespace: `v1` events (unchanged), `a1` alerts, `i1`
incidents. `decodeAlertCursor` and `decodeIncidentCursor` check `parts[0]` exactly where
`decodeEventCursor` already does, so a cross-surface cursor fails with the same error class and the same
400 a malformed one gets. No new failure mode is introduced, only a refusal where there was silence.

**THIS IS NOT THE AUTHORITY REQUIREMENT and must not be read as one.** The tag says "this position
belongs to the alerts walk". It never says who may walk it. Role, tier and identity are still never
encoded, and authority is still re-derived per page from the credential.

REJECTED — no tag, relying on each handler calling its own decoder. That is true of today's call sites,
but the encoded bytes are what a client holds, bookmarks and replays; nothing about an opaque blob tells
a client which surface it came from, and a client that pastes one into the wrong route deserves a
refusal rather than a plausible lie.

## The keyset predicate is appended LAST, after every existing filter

Exactly as `/events` does it: the boundary is a row-wise comparison against the full `ORDER BY` tuple, so
the walk resumes at the row after the last one returned.

    (detected_at, id) < ($n-1, $n)   ORDER BY detected_at DESC, id DESC   LIMIT limit+1
    (last_seen,   id) < ($n-1, $n)   ORDER BY last_seen   DESC, id DESC   LIMIT limit+1

`has_more` comes from over-reading one row; the probe row is discarded so `limit` means what it says; the
cursor is built from the **last kept** row, because taking it from the probe would skip that row on the
next page.

SIMPLIFICATION over `/events`: `peerAlertColumns` already selects `id`, and `StoredIncident.ID` is
already public — so the cursor is built straight from the last kept row. The parallel `ids []int64` slice
`SearchTelemetryPage` carries is a workaround for `EventRow` deliberately omitting `id`, and must not be
copied here where there is nothing to work around.

## Per-surface concrete page types, not a generic `Page[T]`

    AlertPage{Rows []PeerAlert; HasMore bool; NextCursor string `json:"next_cursor,omitempty"`}
    IncidentPage{Rows []StoredIncident; HasMore bool; NextCursor string `json:"next_cursor,omitempty"`}

REJECTED — `Page[T any]`. It saves about nine lines. Against it: there are no generics anywhere in
`internal/` despite the toolchain supporting them, and `EventPage` itself is concrete in precisely the
case generics exist for. Introducing the first generic type in `internal/` as a side effect of "extend
pagination to three routes" is a larger structural decision than this ticket, and belongs to its own
proposal where it can be argued on its merits.

## `/search` is folded in; `?rule=cross_domain` is explicitly out

`SearchPeerAlerts` has the identical defect and is the same function `/alerts` reads through underneath.
Building `SearchPeerAlertsPage` as the paginated primitive and keeping `SearchPeerAlerts` as its thin
`.Rows` wrapper means the bare-list callers (the saved-search runner, a dozen tests) are unchanged and
the two views cannot disagree about what a page contains. Fixing `/alerts` and `/search` separately would
reproduce exactly what D482 named as the real defect: the shape, not the individual missing rows.

`GET /incidents?rule=cross_domain` is out of scope, said plainly rather than omitted.
`CorrelateCrossDomain` is a live `GROUP BY entity_id` aggregate over a rolling window, computed fresh per
call, with no persistent per-row walk order. "The row after this one" is not defined across a
re-aggregated `GROUP BY`; a cursor into it would be a position in a result set that no longer exists.
**Post-review correction.** The first cut left a `cursor=` here SILENTLY IGNORED — answering 200 and page
1 — with a doc comment saying so, on the same route and the same parameter that the burst branch 400s, in
a function whose own comment claims every parameter is fail-loud. One URL, two behaviours. It is now a
400. And the branch answers in the SAME `{rows, has_more}` envelope as the walkable one: a bare array
here meant a console decoding `body.rows` got `undefined` and rendered an empty list while incidents
existed — a wrong answer that looks complete, on the surface this change exists to make honest. Go turns
that into a loud unmarshal error; a browser does not. `has_more` is structurally `false` (the rule applies
no cap, so the answer is complete) and the type carries no continuation field at all, which is stronger
than emitting an empty one.

## `/incidents` is not `/events` wearing a different column name

`fleet_telemetry` rows are append-only. `incidents` rows in `state='open'` are **not**:
`MaterializeIncidents` upserts the same row with `last_seen = EXCLUDED.last_seen`, and it runs both from
the HTTP handler on every `GET /incidents` and from a leader-only background loop, independent of any
operator's walk.

**Post-review correction, and it makes the residual NARROWER than argued below.** `last_seen` is
`max(detected_at)` over the subject's alerts in the window — no writer of that column uses `now()`. So
the upsert is IDEMPOTENT: a materialization pass that finds no new alerts rewrites the value it already
stored. Re-materializing on every page of a walk therefore does NOT push every open incident above the
boundary; only an incident that actually absorbed a new alert moves. The residual is bounded by live
detection, not by walk depth, which is what makes accepting it reasonable rather than merely convenient.
A test pins the idempotence, with its own vacuity guard (a new alert DOES move it).

So an incident **not yet reached** can have its `last_seen` pushed forward mid-walk, moving it from
"deeper in the walk" to "newer than the cursor". Because a keyset walk only moves one direction from a
fixed boundary, that row becomes unreachable for the remainder of the walk. Not duplicated, not silently
miscounted: genuinely absent from this page sequence, resurfacing at the top of a fresh walk.

**Accepted and documented, no snapshot built.** Three reasons.

1. CONSOLE-6's own design ruled a stable snapshot out of scope for all keyset pagination here — "a true
   snapshot needs a transaction or a watermark and is a separate decision". Building one only for
   `/incidents` contradicts the precedent this change extends.
2. The exposure is bounded to `state='open'` rows. Once acknowledged, the upsert's `WHERE state='open'`
   conflict target stops matching and a later burst opens a **new** row — so a walk over
   acknowledged/closed history, which is the deep-page case that motivates pagination at all, behaves
   exactly like `/events`.
3. The UX outcome is arguably correct. An incident that just absorbed a new burst has earned its place
   back at the top, and "restart your walk to see it" describes "this got more urgent while you were
   looking elsewhere", not a corruption.

What must not happen is leaving it undiscovered. It is stated here, and a test pins its shape — an
acknowledged incident deep in a walk is still reached exactly once while an unvisited open incident is
bumped mid-walk — so a regression cannot turn acceptable staleness into silent loss of immutable history.

`MaterializeIncidents` stays **unconditional**, not gated on `cursor == ""`. Gating it would make page 2
silently stop reflecting a rule change the client made between requests while page 1 applied it — a
self-inflicted version of the same "quietly changes meaning mid-walk" problem. And it would buy nothing,
because the background correlation loop mutates the same rows regardless.

## Residuals, stated rather than omitted

- **Open incidents mutating mid-walk** (above). Bounded to `state='open'`; acknowledged history is stable.
- ~~**`?cursor=` is ignored on `?rule=cross_domain`**~~ — FIXED post-review: it is a 400, and that branch
  now shares the envelope. No longer a residual.
- **`/searches/run` still returns bare, capped arrays** with no `has_more`, for alerts, events and logs,
  while the live endpoints return pages — so `/search?subject=X` says `has_more:true` where
  `/searches/run?name=X` returns 100 rows and says nothing. Not fixed here: `/logs` has no page function,
  and paging two of three surfaces would make `results` mean a different shape depending on `surface`,
  which is a worse answer for a console than a uniform one. Bounded today by there being no scheduled
  runner — every caller is a human on `GET /searches/run` who can re-ask with a `limit`. The false claim
  that a saved search "cannot diverge" from the live endpoint has been removed from the code.
- **`peer_alerts` has no index on `detected_at`**, so a deep keyset walk is a sort over a full scan
  regardless of pagination. Pre-existing; `/events` shipped without a composite index too (it leans on
  `fleet_telemetry_sweep_idx`). Following that precedent, no index is added here, but it is named as a
  reasonable follow-up rather than quietly matched.
- **The response envelope changes shape** on three routes (bare array → `{rows, has_more, next_cursor?}`),
  the same breaking-but-accepted change CONSOLE-6 made for `/events`.
