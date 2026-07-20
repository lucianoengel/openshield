## 1. Toolchain

- [x] 1.1 protoc 3.21.12 + protoc-gen-go available; `make proto` wired. NOT YET pinned in
      docs/brief.md — reproducibility across machines is still open (protoc version drift can
      change generated output)
- [x] 1.2 Add `make proto` (or equivalent script) generating `proto/openshield/v1/*.proto` into
      `internal/core/corev1/`
- [x] 1.3 CI check: regeneration produces no diff. Test: run generation in CI and
      `git diff --exit-code` on the generated tree

## 2. Event contract

- [x] 2.1 Define `Event` in `proto/openshield/v1/event.proto` — `event_id`, `agent_id`,
      `connector_id`, `sequence`, `observed_at`, subject, purpose
- [x] 2.2 Define the `Purpose` enum and the pseudonymous `Subject` message
- [x] 2.3 Define the filesystem subject as a `oneof { resolved_path | file_handle }` with a
      discriminator — provisional pending T-005 (see design.md, Open Question 1)
- [x] 2.4 Validation: reject an Event missing any provenance field. Test: table-driven cases,
      one per omitted field
- [x] 2.5 Test: sequence gaps are detectable — emit 1, 2, 4 and assert the consumer reports
      exactly one missing
- [x] 2.6 **Privacy test**: serialize fixture Events built from known identity strings and scan
      the bytes for those strings; assert none appear. Proves "no direct identifier in the
      event stream" by evidence, not by field inspection
- [x] 2.7 **Schema test**: assert `Event` declares no `bytes` field outside an explicit
      allowlist, so adding a content-capable field fails CI

## 3. Classification contract

- [x] 3.1 Define `LocalClassification` (host-only) in `classification.proto`
- [x] 3.2 Define `ClassificationSummary` (wire) with exactly: `detector_type`, `confidence`,
      `match_count`, `event_id`
- [x] 3.3 Define the closed `DetectorType` enum — not a string (a free-form name can itself leak
      what it detected)
- [x] 3.4 **Schema test**: assert `ClassificationSummary`'s field set is exactly those four, so
      any added field fails CI
- [x] 3.5 **Privacy test**: classify fixtures containing known CPF/SSN/card values, serialize
      the summary, and assert the bytes contain neither any substring of the fixture values nor
      any MD5/SHA-1/SHA-256/HMAC digest of them (digests computed over the fixture set at test
      time)
- [x] 3.6 **Schema test**: assert `ClassificationSummary` declares no vector, float-array or
      fingerprint field (embeddings are content — D11)

## 4. Decision contract

- [x] 4.1 Define `Decision` in `decision.proto` — `decision_id`, `action`, `confidence`,
      `reason`, `policy_id`, `policy_version`, `event_id`
- [x] 4.2 Define the closed `Action` enum: `UNSPECIFIED`, `ALLOW`, `ALERT`, `BLOCK`,
      `QUARANTINE_LOCAL`, `ENCRYPT_LOCAL`
- [x] 4.3 **Schema test**: assert `action` is an enum, its members are exactly the six above,
      and no sibling field carries a URL, host, path or command. Adding an action must require
      editing this test — the intended speed bump (D14)
- [x] 4.4 Validation: reject `ACTION_UNSPECIFIED` on any Decision leaving the policy engine, and
      reject unknown enum values rather than defaulting them. Test: both paths asserted
      explicitly, including that an unknown value does NOT become ALLOW
- [x] 4.5 Validation: confidence is mandatory and bounded to [0.0, 1.0]. Test: missing, -0.1,
      1.1 all rejected; no implicit default of 1.0
- [x] 4.6 **Schema test**: assert `Decision` carries no classifier ID, pattern, model reference
      or matched content — explainable to an investigator, opaque to an enforcer

## 5. Enforcer isolation

- [x] 5.1 Define the `Enforcer` interface in `internal/core` accepting only `*Decision`
- [x] 5.2 **Negative compile test**: a fixture package where an enforcer references a
      Classification, with CI asserting it fails to compile AND that the failure message matches
      the expected symbol error — not merely that the build exited non-zero (design.md risk:
      a typo would otherwise make this pass for the wrong reason)

## 6. Phase 1 behaviour

- [x] 6.1 Test: a Decision of `ACTION_BLOCK` in a Phase 1 configuration is recorded and no
      enforcer is invoked (D1 — the contract exists, execution is deferred)
- [x] 6.2 Test: purpose mismatch between Event and policy is refused and the refusal recorded

## 7. Wiring and docs

- [x] 7.1 Add the schema, privacy and negative-compile checks to `.github/workflows/ci.yml`,
      replacing the corresponding placeholder comment
- [ ] 7.2 Update `docs/plan-phase1.md`: mark T-003 done, and record the T-005 dependency on the
      `oneof` in case the spike contradicts it
- [ ] 7.3 Run `/opsx:sync` to fold these delta specs into `openspec/specs/`

## Verification performed

Guards were mutation-tested rather than assumed — a schema test that never fails
is indistinguishable from no test:

| mutation | caught by |
|---|---|
| added `bytes sample` to `ClassificationSummary` | `TestClassificationSummaryFieldSetIsExact`, `TestClassificationSummaryCannotCarryContent` |
| added `string destination_url` to `Decision` | `TestDecisionCarriesNoParameters` |
| added `ACTION_UPLOAD` to the enum | `TestActionEnumIsClosed` |
| enforcer taking a `LocalClassification` | compiler, asserted on the specific error text |

The privacy test also self-checks for vacuousness: it asserts the *local* form
does contain the fixture secret before asserting the wire form does not.
