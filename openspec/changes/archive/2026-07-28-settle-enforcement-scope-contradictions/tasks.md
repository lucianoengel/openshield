## 1. Teach the tools removal and renaming

- [x] 1.1 `scripts/spec-store-audit.py`: track the LAST operation per requirement (ADDED / MODIFIED /
      REMOVED / RENAMED) instead of treating every heading as required; a removed requirement is not a
      loss, a removed-then-re-added one is.
- [x] 1.2 `scripts/spec-store-restore.py`: same semantics — never restore a requirement a later change
      removed, and follow a rename to the new heading.
- [x] 1.3 `internal/doccheck.CheckSpecStore`: same semantics, with fixture tests for removed,
      removed-then-re-added, renamed, and an unknown section still refused.
- [x] 1.4 Keep the refusal for genuinely unknown sections, and prove it still fires.

## 2. Settle the two contradictions

- [x] 2.1 `enforcement`: remove "Post-decision enforcement contains, it does not prevent" and add
      "Prevention is claimed only where the product prevents".
- [x] 2.2 `decision-contract`: remove "Phase 1 records decisions without acting on them" and add
      "Recording is unconditional; acting is opt-in".
- [x] 2.3 `spec-store-integrity`: add the removal/rename requirement.
- [x] 2.4 Confirm no OTHER surface still carries the retired claims — README, INVARIANTS, docs — since a
      spec corrected while the README still says the opposite has moved the contradiction, not settled it.

## 3. Verify and land

- [x] 3.1 `scripts/spec-store-audit.py` reports zero missing WITH the removals in place.
- [x] 3.2 `openspec validate --specs --strict` passes on every capability.
- [x] 3.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 3.4 Record the unwired file-open prefilter in `docs/unwired-audit.md`.
- [x] 3.5 Commit with a D-number and archive WITH the spec sync.
