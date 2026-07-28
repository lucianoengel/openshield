## 1. The audit, before anything is written

- [x] 1.1 Write `scripts/spec-store-audit.py`: for every `openspec/changes/archive/*/specs/<cap>/spec.md`,
      parse its `## ADDED` / `## MODIFIED` sections and `### Requirement:` headers, and report each header
      absent from `openspec/specs/<cap>/spec.md`, naming the archived change it came from.
- [x] 1.2 Make it fail loudly on any section type other than ADDED/MODIFIED, naming the section and the
      change — never skip one.
- [x] 1.3 Record the baseline it prints (measured: 170 distinct missing across 20 capabilities, 55 intact) so the
      reconstruction can be proven complete against a number captured before it ran.

## 2. The reconstruction

- [x] 2.1 Write `scripts/spec-store-restore.py`: replay each capability's archived deltas in
      chronological order (archive directories are date-prefixed), later occurrence winning, and APPEND to
      the existing capability file every requirement whose header is absent.
- [x] 2.2 Never remove or rewrite an existing block — the 28 requirements with no archived source must
      survive untouched, and the diff must be pure addition.
- [x] 2.3 Report, without changing them, the 14 requirements whose current body differs from the latest
      archived version.
- [x] 2.4 Run it; confirm `git diff --stat` shows additions only, and that the 55 intact capabilities are
      unmodified.
- [x] 2.5 Read the restored requirements for contradictions with current behaviour and record each one in
      `design.md` under "Open questions" — restore the text as written, reconcile nothing.

## 3. The guard

- [x] 3.1 Add `CheckSpecStore` to `internal/doccheck`: every archived delta's requirement headers are
      present in its capability file; returns findings naming capability, requirement and source change.
- [x] 3.2 Fixtures proving BOTH directions — a capability missing an archived requirement fails, and a
      capability carrying requirements with no archived source passes (that is legitimate).
- [x] 3.3 Wire it into the existing doccheck test so it runs under `make quick` and `make all`.
- [x] 3.4 Mutation: delete one restored requirement from a capability file and confirm the guard fails
      naming it; restore.

## 3b. Structure the clobber also destroyed (discovered during 2)

- [x] 3b.1 Reinstate the `## Requirements` heading in the 37 capabilities that lost it, from the same
      re-runnable script.
- [x] 3b.2 Reflow 4 requirements whose SHALL/MUST sat below the first line, which the validator requires.
      Meaning-preserving only.
- [x] 3b.3 Author a `## Purpose` for the 19 capabilities that lost theirs, each summarising the
      requirements now in that file. Recorded in design.md as AUTHORED, not restored.

## 4. Verify and land

- [x] 4.1 `scripts/spec-store-audit.py` reports zero missing.
- [x] 4.2 `openspec validate --specs --strict` passes on every capability.
- [x] 4.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 4.4 Record the round in `docs/unwired-audit.md`: the spec store is the seventh defect shape — a
      source of truth that loses its history through the tool meant to maintain it.
- [x] 4.5 Commit with a D-number, and archive this change WITH the spec sync (the option whose absence
      caused this).
