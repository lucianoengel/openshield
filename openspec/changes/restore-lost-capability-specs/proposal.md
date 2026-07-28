## Why

**186 of 558 requirements written for this project are missing from the spec store.** Twenty of the
seventy-five capability files have been overwritten with the contents of whichever delta was synced last:
`openspec/specs/control-plane/spec.md` is one requirement long, and it is the SOAR-6 delta verbatim —
forty-three requirements from thirty-six other changes are simply not there. `audit-ledger` keeps 5 of 22,
and the ones it lost include *"Every entry commits to its predecessor"*, which is the ledger's central
claim.

The root cause is not only the archive step's "archive without syncing" option, which was taken
repeatedly. It is that when sync DID run it **replaced** the capability file with the delta instead of
merging into it. Both paths lose requirements; the second loses them while appearing to have worked.

The harm is specific, and it is not that the specs are wrong. **They are incomplete, and an absent
requirement is indistinguishable from a capability nobody ever asked for.** The next person to work on
the ledger opens a spec that never mentions hash chaining and reasonably concludes the design is theirs
to make. Every future `/opsx` change inherits the loss compounded, because a delta is written against —
and validated against — whatever the capability file currently says.

Nothing is unrecoverable: every archived delta still holds what it added. This is a reconstruction, and
the moment to do it is before the next change is written against a file that is missing most of itself.

## What Changes

- **A reproducible audit.** A check that, for every archived delta, compares its `### Requirement:`
  headers against the merged capability file and reports what is absent. The gap becomes measured rather
  than estimated, and the same check proves the reconstruction complete afterwards.
- **The reconstruction.** Archived deltas are replayed into their capability files in chronological
  order (the archive directories are date-prefixed), honouring `## ADDED` and `## MODIFIED` sections:
  a later MODIFIED supersedes the earlier ADDED it revises. Only these two section types occur in this
  archive (266 ADDED, 35 MODIFIED, no REMOVED or RENAMED), so the replay handles what is actually there
  and FAILS LOUDLY on a section type it has not been taught rather than dropping it.
- **A guard, in `internal/doccheck`.** The same comparison as a test, so a future change that archives
  without syncing — or a sync that clobbers — fails the gate instead of silently costing another
  capability its history. `doccheck` already owns the claim-surface and decision-register guards; this is
  the third guard of the same kind and belongs beside them.
- **Contradictions are recorded, never reconciled.** Where a recovered requirement disagrees with what
  the code now does, it lands as written and the disagreement goes into `design.md` for a human to
  settle. Inventing a requirement to match the code is how a spec stops being a specification.

**No behaviour changes, no migration, no proto change.** This is a documentation reconstruction plus one
test.

## Capabilities

### New Capabilities

- `spec-store-integrity`: the spec store's own contract — every requirement an archived change introduced
  is present in its capability file, and the check that keeps it true.

### Modified Capabilities

None in the requirement-changing sense. Twenty capability FILES gain back requirements they already had —
`control-plane`, `enforcement`, `audit-ledger`, `inline-prevention`, `packaging`, `peer-ueba`,
`network-threat-intel`, `unified-alerts`, `event-contract`, `four-eyes-approvals`,
`exfil-channel-awareness`, `clipboard-monitor` and the rest — but no requirement is authored here. Every
line restored is a line this project already reviewed and shipped, recovered from its archive, so these
are not deltas and this change writes no delta spec for them.

## Impact

- `openspec/specs/*/spec.md` — twenty files grow; fifty-five are untouched and must be proven untouched.
- `internal/doccheck` — one new check plus fixtures, wired into the existing `make all` path.
- No runtime code, no configuration, no database, no dependency.
- **Risk to name plainly:** the replay edits the source of truth for the whole project, so it must be
  mechanical and re-runnable, and its output has to be diffable — a hand-merged file nobody can regenerate
  would be the same problem again with better contents.
