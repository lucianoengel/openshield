# Tasks — CONSOLE-6b

- [x] 1. `alertCursor` / `incidentCursor` sibling types in cursor.go, each with its own version tag
      doubling as a namespace; decoders refuse a tag that is not theirs.
- [x] 2. `AlertFilter.Cursor`; `AlertPage`; `SearchPeerAlertsPage` with the `(detected_at, id) < (…)`
      keyset predicate appended after every existing filter; `SearchPeerAlerts` becomes the `.Rows`
      wrapper so its existing callers are unchanged.
- [x] 3. `IncidentPage`; `RecentIncidentsPage(ctx, limit, cursor)` with `(last_seen, id) < (…)`;
      `RecentIncidents` becomes the `.Rows` wrapper.
- [x] 4. `/alerts` and `/search` route through `SearchPeerAlertsPage`; `parseAlertFilter` validates the
      cursor at the edge so a malformed one is a 400 rather than a query-layer error.
- [x] 5. `/incidents` burst branch routes through `RecentIncidentsPage`; `?rule=cross_domain` offers no
      cursor (superseded by task 10: it now REFUSES one and shares the envelope).
- [x] 6. Tests + mutations: walk completeness on both surfaces; the deliberate TIE fixture; truncation
      reports itself and its negative half; malformed cursor is 400; a cross-surface cursor is refused
      (the mutation that proves the namespace is load-bearing); cursor carries position and never
      authority; page shape; the incident-mutation residual pinned.
- [x] 7. Integration test against the shipped binary: one walk per surface over real HTTP with a real
      operator credential.
- [x] 8. Docs: decision row, roadmap status, spec sync.

## Post-review (two independent reviews of the working tree, before the change was committed)

- [x] 9. **The saved-search freeze, on BOTH surfaces.** `parseAlertFilter` and `parseEventFilter` both
      read `cursor=`, and both are what `validateSearch` accepts a saved search with and
      `runResolvedSearch` executes it through — so a saved hunt could capture a cursor and be frozen at
      the instant it was saved, forever, silently. `rejectStoredCursor` refuses it at SAVE (the analyst
      is told) and at RUN (the searches already stored are the ones already frozen). The events half is
      a pre-existing defect shipped in D481, not one this change introduced; one reviewer argued the
      events surface was unaffected and was wrong — `event_search.go` sets `f.Cursor` and `SurfaceEvents`
      dispatches to it.
- [x] 10. **`?rule=cross_domain` refuses a cursor** instead of answering 200 and page 1 — one route, one
      parameter, one behaviour — and answers in the SAME `{rows, has_more}` envelope as the walkable
      branch, so a console decoding `rows` does not render an empty list while incidents exist. No
      `next_cursor` field exists on that type at all.
- [x] 11. **The recomputed-rule requirement, which shipped with no test**, is asserted: the envelope, the
      absence of any continuation (asserted on the raw body, since a struct without the field cannot
      report one), and the refusal — with the cursor-free request as the positive half.
- [x] 12. **`MaterializeIncidents` moved below the limit/cursor validation.** It is a write that can
      INSERT an incident and page the SOC; running it first meant a request that then 400'd had already
      mutated and possibly woken someone. Pre-existing for `limit`; the new cursor check inherited it.
- [x] 13. **`RecentPeerAlerts` deleted.** Unreachable from any route after task 4, exported, and carrying
      `ORDER BY detected_at DESC` with no id tiebreaker and no cap — the exact defect this change built a
      tie fixture against, left lying where the next `/alerts`-shaped route would find it.
- [x] 14. **Two false claims corrected, and the fact behind them turned into a test.** No writer sets
      `last_seen = now()`; it is `max(detected_at)` per subject. The tiebreaker is still required (real
      ties exist) but the stated reason was wrong — and the true fact is BETTER than the design argued:
      re-materializing with no new alerts is idempotent, so the unconditional materialization on every
      page does not push open incidents ahead of the walk. The residual is bounded by live detection, not
      by walk depth. Pinned by a test with its own vacuity guard.
- [x] 15. **The unenforced spec sentence softened** rather than asserted: a bumped row MAY be absent from
      the rest of the walk is a permitted weakness, not a requirement — requiring it would make a future
      improvement a violation. The test observes it with `t.Logf`, deliberately.
- [x] 16. **`/searches/run`'s false "cannot diverge" claim removed.** It returns bare capped arrays with
      no `has_more` while the live endpoints return pages. NOT fixed here (see the residual in D484):
      /logs has no page function, and paging two of three surfaces would make `results` mean a different
      shape per surface.
- [x] 17. Tie-fixture mutation arithmetic corrected (2 of 5 alerts, 1 of 3 incidents — both re-executed).
