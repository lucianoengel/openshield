## 1. Error taxonomy

- [x] 1.1 `core.Category(err) string`: errors.Is against the sentinels → stable slugs
      (stage_failed, timeout, not_recorded, reentry, no_decision, ledger_unavailable, unreachable,
      unknown)
- [x] 1.2 **Test**: each sentinel (wrapped) categorises correctly; unknown → "unknown".
      `TestErrorCategory`

## 2. Dispatcher logging

- [x] 2.1 `Dispatcher.Logger *slog.Logger`, nil-safe via a discard default; a `log()` helper
- [x] 2.2 Log every terminal outcome in the outcome switch / report: event_id, stage, kind,
      severity, category, at a slog level matching the severity
- [x] 2.3 No control-flow change — the same errors are still returned

## 3. Tests

- [x] 3.1 **Test**: a failing stage emits a log with event_id + category=stage_failed.
      `TestFailureIsLogged`
- [x] 3.2 **Test**: a timeout logs category=timeout at warn+; a not-recorded append logs
      category=not_recorded. `TestTimeoutAndNotRecordedLogged`
- [x] 3.3 **Test**: a content marker in an event never appears in the log. `TestLogsCarryNoContent`

## 4. Wire + docs

- [~] 4.1 The wiring point is `Dispatcher.Logger` (any `*slog.Logger`). No dispatcher is built in
      `cmd/*` yet — the live pipeline is assembled from tested components but not wired into a
      cmd binary in Phase 1 — so whatever assembles the agent pipeline sets `Dispatcher.Logger`
      to a stderr handler. Stated honestly rather than adding a dead cmd stub
- [x] 4.2 Note in `docs/decisions.md` (new D-number): structured logging via slog, correlation id =
      event id, category taxonomy, no content in logs, OTel deferred
- [x] 4.3 Mark T-028 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| the outcome log dropped | `TestFailureIsLogged`, `TestTimeoutAndNotRecordedLogged` |
| Category by string-match (breaks wrapped errors) | `TestErrorCategory` |

Every terminal outcome logs event_id + stage + kind + severity + category at a
level matching the severity (a failing stage → category=stage_failed; a timeout →
category=timeout at WARN; a failed audit append → category=not_recorded). The
taxonomy matches by `errors.Is` so wrapped sentinels categorise correctly. A log
is a wire (D10): `TestLogsCarryNoContent` plants a content marker on a decision
reason and asserts it never reaches the log. No control-flow change — the same
errors are still returned. Wiring point is `Dispatcher.Logger`; no live dispatcher
exists in cmd yet, stated rather than stubbed. Docs: D43.
