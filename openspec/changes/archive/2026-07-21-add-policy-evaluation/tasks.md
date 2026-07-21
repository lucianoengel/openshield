## 1. The capability-restricted engine

- [x] 1.1 `internal/policy` package. Build `ast.CapabilitiesForThisVersion()`, filter `Builtins`
      to a pure-operator allowlist (comparison, arithmetic, membership, string/object/array ops);
      exclude all network, time, randomness, jwt, opa.runtime, io builtins
- [x] 1.2 Prepare the query once (`rego.PrepareForEval`) with the restricted capabilities and the
      loaded policy; a policy referencing an excluded builtin fails here
- [x] 1.3 **Test**: a policy calling `http.send` fails to load; a policy calling `time.now_ns`
      fails to load. Assert BEHAVIOUR, not the allowlist contents. `TestForbiddenBuiltinsRejected`

## 2. Evaluate → Decision

- [x] 2.1 Build the input document from `State`: purpose, event kind/subject, classification hits
      (type/confidence/count), context (null in Phase 1)
- [x] 2.2 Evaluate at `data.openshield.decision`; parse `{action, confidence, reason}`
- [x] 2.3 Closed action mapping table `string → corev1.Action`; unknown/missing action → failed
      outcome, never ALLOW
- [x] 2.4 No decision produced → explicit ALLOW with reason "no policy rule matched" (a normal
      decision, not a failure)
- [x] 2.5 Stamp `policy_id`, `policy_version`, `decision_id`, `decided_at`, `context_version`
      (from State) on the Decision; confidence from the classification, never 1.0
- [x] 2.6 Implement `core.Stage` (`Name`, `Run`); `Run` returns `core.Decided(d)`

## 3. The default Phase-1 policy

- [x] 3.1 A local `.rego` policy: alert when a checksum-backed detector (CPF/card) exceeds a
      confidence threshold; allow otherwise. Emits ALERT/ALLOW only — never BLOCK (observe-only, D1)
- [x] 3.2 Embed it with `go:embed` so the binary has a working default; a path/override can come
      later

## 4. Tests — the contract

- [x] 4.1 **Test**: a policy over a CPF hit yields a well-formed ALERT Decision.
      `TestCPFHitAlerts`
- [x] 4.2 **Test**: identical Event dispatched twice → `DecisionsEquivalent`. `TestDeterministic`
- [x] 4.3 **Test**: an unknown action name → failed outcome, not ALLOW. `TestUnknownActionFails`
- [x] 4.4 **Test**: every `Action` enum value has exactly one mapping and round-trips.
      `TestActionMappingIsComplete`
- [x] 4.5 **Test**: a non-matching policy → explicit ALLOW with a "no rule matched" reason.
      `TestNoMatchIsReasonedAllow`
- [x] 4.6 **Test**: no Decision is emitted with confidence 1.0. `TestConfidenceIsNeverCertainty`

## 5. Wire into the pipeline

- [x] 5.1 Register the policy stage after classification in the dispatcher wiring (wherever the
      pipeline is assembled); confirm it produces a Decision the audit sink records
- [x] 5.2 **Test**: classification hit → policy stage → `core.Decided` → audit sink appends an
      entry with the Decision. (Uses the in-memory recording ledger from the core tests)
- [x] 5.3 Confirm `scripts/check-core-deps.sh` still passes — OPA lives in `internal/policy`, not
      core; core must not gain an OPA/net/http dependency

## 6. Docs

- [x] 6.1 Record the restricted-capability decision in `docs/decisions.md` (new D-number):
      network/clock/randomness excluded → distributed policy is safe-by-construction and decisions
      are deterministic
- [x] 6.2 Mark T-008 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| capability restriction removed (full builtin set) | `TestForbiddenBuiltinsRejected` — http.send and time.now_ns loaded |
| unknown action falls through to ALLOW | `TestUnknownActionFails` |
| confidence ceiling raised to 1.0 | `TestConfidenceIsNeverCertainty` |

**A bug the determinism/confidence test found.** OPA returns Rego numbers as
`json.Number`, not `float64`. The first cut of `confidenceFrom` type-asserted
`float64`, so it silently ignored every policy-supplied confidence and fell back
to the classification max — and `TestConfidenceIsNeverCertainty` passed for the
wrong reason (the policy's `1.0` was discarded, not clamped). Caught by making
the test first assert that a sub-certain policy value (0.4) flows through
unchanged, then that 1.0 is clamped. Fixed with `regoFloat`, which reads both
forms. The clamp mutation is now genuinely caught.

Core stays clean of OPA and net/http (`check-core-deps.sh`); OPA is confined to
`internal/policy`. The full observe path runs end to end in
`TestPolicyDecisionReachesTheLedger`: classify → policy → `core.Decided` → audit
sink append.
