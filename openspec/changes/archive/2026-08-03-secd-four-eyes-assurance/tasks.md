# Tasks — SEC-D four-eyes assurance

- [x] 1. `AssessFourEyes` / `FourEyesAssurance` reading both operator-identity switches, with each gap
      named in the operator's own vocabulary.
- [x] 2. `FourEyesStartupNotice`, returned rather than logged so the sentence is testable.
- [x] 3. Migration 046: `approvals.assurance`, additive, existing rows left empty rather than guessed.
- [x] 4. `ResolveApproval` stamps the assurance; `ApprovalFor` projects it; the `Approval` struct and its
      JSON carry it.
- [x] 5. `OPENSHIELD_FOUR_EYES_REQUIRE_STRONG` gating GRANTS only, declared in `ServerFields`.
- [x] 6. `openshield-server` states the assurance at every boot.
- [x] 7. Tests: weak and strong are recorded; a weak grant is refused under REQUIRE_STRONG and stays
      pending; hardening lets the same approval through; a denial is never gated and is still recorded
      weak; the notice names only the switch that is off, and confirms when hardened.
- [x] 8. Mutation-verify all five.
- [x] 9. Integration: the real server prints the weak notice naming all three keys, and the strong one
      when hardened.
- [x] 10. Spec delta + roadmap.
