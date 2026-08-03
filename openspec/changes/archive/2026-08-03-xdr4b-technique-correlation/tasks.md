# Tasks — XDR-4b technique-level correlation

- [x] 1. `internal/attack`: a single `allTechniques` list, `Known(id)` derived from it, and a test
      that every technique the mapper can emit is `Known`.
- [x] 2. `proto/openshield/v1/decision.proto`: `repeated string techniques = 10;` + regenerate.
- [x] 3. `internal/core/validate.go`: `ValidateDecision` refuses an unknown technique id.
- [x] 4. `internal/policy/policy.go`: attach `attack.IDs(attackSignals(st))` to the produced Decision;
      prove a policy that *declares* a technique does not put it on the Decision.
- [x] 5. Migration `044_unified_alert_techniques.sql`: additive `techniques TEXT[]` column.
- [x] 6. `AlertRecord.Techniques` + insert; `projectDecisionAlert` passes the validated ids.
- [x] 7. `CrossDomainRule.TechniqueSequence`, `matchesTechniqueSequence` (strictly increasing alert
      index), `CrossDomainIncident.Techniques`, the space-joined aggregation.
- [x] 8. `technique_sequence` query param, fail-loud on an unknown id.
- [x] 9. Unit tests + mutation verification for each of the above.
- [x] 10. Integration test: end-to-end technique sequence over real Postgres.
- [x] 11. Spec deltas for `attack-mapping` and the cross-domain correlation capability.
