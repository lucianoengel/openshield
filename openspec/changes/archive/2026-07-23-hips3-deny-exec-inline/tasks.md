## 1. ExecEvaluator
- [x] 1.1 `ExecDecider func(ctx, PermissionEvent) (corev1.Action, error)`; `ExecEvaluator{Decider}` implements watchdog.Evaluator — VerdictBlock iff ACTION_DENY_EXEC, error propagates.

## 2. Wire (engine-backed decider)
- [x] 2.1 Engine-backed decider (`internal/agent/execguard`): build EVENT_KIND_PROCESS_EXEC from the permission event → engine.Process → decision.Action. Own package so it imports the engine without a watchdog↔engine cycle.
- [x] 2.2 DenyEnforcer NOT registered — resolved: `engine.Process` runs `enforce()` internally, so with the inline watchdog path registering it would double-apply the deny. Stale "no ExecController to wire" comment replaced with the rationale; DenyEnforcer kept for the async flow-enforcer model.

## 3. Tests (mutation-verified)
- [x] 3.1 ExecEvaluator: DENY_EXEC action → VerdictBlock; ALLOW/ALERT → VerdictAllow; decider error propagates.
- [x] 3.2 Watchdog integration: DENY_EXEC decision → Responder.Deny; ALLOW → Responder.Allow; a slow decider → fail-open Allow (audited).
- [x] 3.3 Mutations: ExecEvaluator returns Allow for DENY_EXEC → the deny test FAILs; it swallows the decider error → the fail-open test FAILs. execguard: wrong kind / dropped pid / swallowed error each FAIL.

## 4. Gate + close
- [ ] 4.1 make all green; cross-compile; restore binaries.
- [ ] 4.2 decisions.md; sync spec; doccheck.
- [ ] 4.3 Archive; commit; push; roadmap.
