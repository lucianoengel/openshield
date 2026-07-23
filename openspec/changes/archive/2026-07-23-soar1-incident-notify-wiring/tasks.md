## 1. Notification kind

- [x] 1.1 Add `KindIncident notify.Kind = "incident"` to `internal/notify/notify.go` with a comment (a correlated incident was raised; pseudonymous, no content).

## 2. Wire materialization → notify

- [x] 2.1 In `MaterializeIncidents` (`internal/controlplane/incidents.go`), change the upsert from `pool.Exec` to `pool.Query`/`QueryRow` with `RETURNING id, (xmax = 0) AS inserted`, scanning the incident id and the insert-vs-update flag per row.
- [x] 2.2 When `inserted` is true, build a `notify.Notification{Kind: KindIncident, Subject: inc.SubjectID, RiskScore: inc.MaxRisk, At: now, ID: fmt.Sprintf("inc_%d", id), Detail: <severity + alert/host count summary>}` and call `s.emit(ctx, n)`. When `inserted` is false (the extend-the-open-incident update), emit nothing.
- [x] 2.3 Keep the loop's existing error-return contract; a persist error still aborts (the row is the record). Emit is best-effort and must not change the returned count or error.

## 3. Tests (real Postgres + httptest webhook, no seeded literals)

- [x] 3.1 `TestMaterializeNewIncidentNotifiesOnce`: seed a real above-threshold burst, `SetNotifier` a webhook counting POSTs, `MaterializeIncidents` then re-`MaterializeIncidents` the same open incident → assert exactly one POST, kind=incident, id=`inc_<id>`.
- [x] 3.2 `TestReMaterializeSameIncidentDoesNotRepage`: covered by 3.1's second call asserting zero additional POSTs (the update path).
- [x] 3.3 `TestDistinctLaterIncidentPagesAgain`: page the first incident, move it out of open (acknowledge/close), seed a new burst, materialize → assert a second POST (distinct `inc_<id>`), proving per-incident (not content-window) dedup.
- [x] 3.4 Ensure test isolation: unique-per-run subject ids (`time.Now().UnixNano()`); confirm `incidents`/`notify_dedupe` are in the `requireDB` drop list or use unique keys.

## 4. Mutation verification

- [x] 4.1 Mutation A — ignore `inserted` (always emit): `TestMaterializeNewIncidentNotifiesOnce` must FAIL (the re-materialize delivers a second POST). Revert.
- [x] 4.2 Mutation B — drop the explicit `ID` (fall back to `notifyID`): `TestDistinctLaterIncidentPagesAgain` must FAIL if the two incidents fall in the same content-window bucket (same kind|subject|window → suppressed). Revert.

## 5. Gate & land

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (run `test` in background; `git checkout -- openshield-*` after any build).
- [x] 5.2 Add decisions.md D-entry; sync the delta into `openspec/specs/control-plane/spec.md`; run doccheck (`go test ./internal/doccheck/`).
- [x] 5.3 Update the roadmap: SOAR-1 DONE; R34-13 tail thread closed; note test #10 now landable; archive the change; commit, `git pull --rebase`, push.
