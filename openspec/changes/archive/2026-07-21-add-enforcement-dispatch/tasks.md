## 1. Enforcement dispatch in the engine

- [x] 1.1 `Engine.Enforcers []core.Enforcer`; after Process produces a Decision (recorded), if an
      enforcer advertises the action, invoke it — with the enforcement TARGET (file path) from the
      engine's event, not the Decision
- [x] 1.2 Audit the enforcement outcome: failure → high-severity "enforcement-failed" entry;
      success → an "enforced" entry. Record BEFORE enforce
- [x] 1.3 No enforcers → no enforcement (observe-only default, D1)

## 2. Quarantine-local file enforcer

- [x] 2.1 `internal/enforcers/quarantine`: Capabilities {QUARANTINE_LOCAL}; `Mover` interface; move
      the flagged file to a 0700 quarantine dir; a real fs mover + a fake

## 3. Tests

- [x] 3.1 **Test**: no enforcers → decide+record, enforce nothing. `TestObserveOnlyByDefault`
- [x] 3.2 **Test**: a QUARANTINE_LOCAL decision → file moved (fake mover) → decision + enforcement
      outcome recorded, in that order. `TestEnforcementDispatchedAndAudited`
- [x] 3.3 **Test**: an enforcer error → high-severity enforcement-failed audit, not swallowed.
      `TestEnforcementFailureAudited`
- [x] 3.4 **Test** (real fs): quarantine moves a real file to the quarantine dir. `TestQuarantineMovesFile`

## 4. Docs

- [x] 4.1 Note in `docs/decisions.md` (new D-number): post-decision enforcement dispatch; record-
      then-enforce; failure audited; observe-only default; CONTAINS not PREVENTS; inline blocking
      deferred (T-002 budget)
- [x] 4.2 Validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| enforcement failure recorded as success (swallowed) | `TestEnforcementFailureAudited` |
| enforcement recorded before the decision / no-op | `TestObserveOnlyByDefault`, `TestEnforcementDispatchedAndAudited` |

No enforcers → decide + record, enforce nothing (observe-only default, D1). A
QUARANTINE_LOCAL decision → the file is moved and the decision + an "enforced"
outcome are recorded, in that order (record before enforce). An enforcer error →
a high-severity "enforcement-failed" entry, never swallowed (D14). The real
filesystem enforcer moves a real file into an owner-only (0700) quarantine dir and
refuses an empty target. The target is supplied by the engine via
`TargetedEnforcer`; the Decision contract is not widened (D39). Docs: D49.
