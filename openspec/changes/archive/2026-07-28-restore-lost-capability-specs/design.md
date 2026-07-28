## Context

The measurement, before any decisions. Every number here is from a script over the tree, not an estimate:

| | |
|---|---|
| capabilities with a spec file | 75 |
| capabilities touched by at least one archived delta | 75 |
| requirement headings introduced across the archive | 558 occurrences, **526 distinct** |
| **absent from their capability file** | **170 distinct** (186 occurrences) |
| capabilities fully intact | 55 |
| capabilities damaged | 20 |
| requirements in a capability file with no archived source | 28, across 17 capabilities |
| requirements present but STALE against the latest archived version | 14, across 12 capabilities |
| headers introduced by more than one archived change | 25 (bodies differ in all 25) |

Worst affected: `control-plane` 43 of 44 missing, `enforcement` 22 of 25, `audit-ledger` 19 of 22,
`inline-prevention` 13 of 17, `packaging` 11 of 13.

The two counts differ because a requirement ADDED and later MODIFIED appears in the archive more than
once. The audit reports DISTINCT requirements — one missing requirement, not three — and 170 is the
number the reconstruction must drive to zero.

**The mechanism, confirmed rather than assumed.** `openspec/specs/control-plane/spec.md` contains exactly
one requirement, and it is the body of `2026-07-26-soar6-response-metrics`'s delta. It is not the last
delta chronologically — `xdr4-cross-domain-correlation` came after it. So the file was not "left behind by
a missing sync"; it was REPLACED by whichever delta was synced last. Two distinct losses are therefore in
play, and only naming both leads to the right guard:

1. archiving without syncing (the archive skill offers it; it was taken repeatedly), and
2. a sync that overwrote the capability file with the delta instead of merging into it.

The second is the more dangerous, because it reports success.

## Goals / Non-Goals

**Goals**
- Every archived requirement present in its capability file, verifiably.
- A reconstruction that is mechanical, re-runnable and reviewable as a diff.
- A guard that fails the gate when this recurs.

**Non-Goals**
- Reconciling specs against code. Where they disagree, the disagreement is recorded, not resolved.
- Rewording, deduplicating or improving any recovered requirement. Everything restored is text this
  project already reviewed.
- Repairing the archive skill's sync path. Worth doing, out of scope here; the guard makes its failure
  loud, which is what stops the next loss.

## Decisions

### Additive merge, not regeneration

The obvious implementation — rebuild each capability file from its archived deltas — is wrong, and the
28 orphan requirements are why. Those exist in capability files with no archived source: some were
authored directly (this session added CASB, DLP-3-wiring, ITSM and exec-IPC requirements by hand in D320
and D321), and regeneration would delete every one of them. A repair that loses requirements while fixing
lost requirements is not a repair.

So the replay starts from the CURRENT file and only ADDS what is absent, appending recovered requirements
in chronological order. **No existing line is removed**, which makes the diff pure addition and therefore
reviewable at a glance — the property that matters most when editing the source of truth for the whole
project.

### The 14 stale bodies are reported, not silently rewritten

Fourteen requirements are present under the right header but carry an older body than the latest archived
version. Replacing them is a content change hiding inside a mechanical repair, and the header-presence
check cannot see the difference either way. They are listed in the reconstruction's output and left for a
separate, deliberate pass. Saying "14 known-stale, untouched" is honest; quietly rewriting fourteen
requirement bodies inside a change described as additive is not.

### Later wins, and the ordering was checked rather than assumed

Of the 25 repeated headers, the section sequences are: 17 `ADDED → MODIFIED`, 5
`ADDED → MODIFIED → MODIFIED`, 1 `ADDED → MODIFIED → MODIFIED → MODIFIED`, and 2 `MODIFIED → ADDED`.
Chronological last-wins is correct for all of them. The two `MODIFIED → ADDED` pairs are out of order —
a later change re-ADDED a requirement an earlier one had already modified — and last-wins still picks the
intended text, so they are noted and not treated as errors.

Only `ADDED` and `MODIFIED` occur in this archive (266 and 35). `REMOVED` and `RENAMED` do not, so the
replay implements the two that exist and **fails on any other section type**. Handling a section by
ignoring it is exactly the behaviour that produced this change.

### Two implementations, deliberately

The one-time reconstruction is a script; the recurring guard is a Go test in `internal/doccheck`. They
parse the same files, which is duplication — accepted, because they have different lifetimes and
different jobs. The script runs once, writes, and its output is a reviewable diff; the guard runs on every
`make all`, never writes, and needs only headers. `doccheck` already owns the claim-surface check and the
decision-register uniqueness check, and this is the third guard of that family.

The guard asserts PRESENCE of headers only. It deliberately does not compare bodies: a body check would
fail on the 14 known-stale requirements and on any future deliberate edit to a capability file, and a
guard that must be suppressed is a guard that gets deleted.

### What the guard does not catch

Stated plainly because the check will be read as stronger than it is:

- it cannot see a requirement that was never written down;
- it cannot see a capability file whose requirement bodies have drifted from the archive (the 14);
- it cannot see a requirement that contradicts the code.

It catches exactly one thing: a requirement this project shipped, disappearing from the file that is
supposed to hold it.

## Risks / Trade-offs

- **The diff is large** — roughly 186 requirement blocks across 20 files. Mitigated by being purely
  additive and machine-generated from an archive that is itself in version control, so any block can be
  traced to the change that introduced it.
- **Restored requirements may contradict current behaviour.** This is likely: `enforcement`,
  `inline-prevention` and `control-plane` have all been reworked since the earliest deltas. Every
  contradiction found while replaying is recorded in this file under "Open questions" for a human to
  settle. None is reconciled here.
- **The archive-sync path is left unrepaired.** The guard converts a silent loss into a failed gate, which
  is the property worth having now; fixing the skill is a follow-up.

## What implementation discovered

**The clobber destroyed document STRUCTURE as well as content, and that is why nobody noticed.** A delta
file is a list of `## ADDED Requirements` sections; a capability file is `## Purpose` then
`## Requirements`. Overwriting the second with the first removed the headings, and `openspec validate`
had been failing on **37 of 75 capabilities** — for weeks. A store whose validator is already red reports
nothing when it goes redder. The alarm that would have caught this was itself broken by the same event.

So the repair grew three parts beyond the plan, and each is worth separating by how much authoring it
required:

- **Mechanical, no authoring:** reinstating the `## Requirements` heading in 37 capabilities. Purely
  positional, folded into the restore script so it is re-runnable.
- **Meaning-preserving reflow, 4 requirements:** the validator requires SHALL/MUST on the requirement's
  FIRST LINE, and four requirements had it on the second. Sentences were reordered, nothing was added or
  removed.
- **Authored, 19 capabilities:** a `## Purpose` section. These were NOT recovered, and the distinction
  matters. The archived proposals do carry a line per capability, but it describes the CHANGE, not the
  capability — `control-plane`'s earliest is "alerts are delivered via a notifier (webhook),
  best-effort", which as a purpose for the whole control plane would be confidently wrong. Each purpose
  was instead written as a summary of the requirements now in that file, which is checkable against the
  file itself. This is the one part of the change that is new prose, and it is called out rather than
  folded in.

## Open questions

Contradictions found between a restored requirement and current behaviour. **Restored as written and
left for a human**, per the change's own rule: inventing a requirement to match the code is how a spec
stops being a specification.

1. **`enforcement`: "Post-decision enforcement contains, it does not prevent"** says plainly that
   *"inline blocking within the permission window is not provided"* and that it *"stays deferred because
   the pipeline cannot complete in the permission window (T-002)"*. Both are now false: HIPS-3 blocks an
   exec inside the fanotify permission window and NIPS-1 drops a flow at L4. The `inline-prevention`
   capability supersedes this requirement in practice but has never said so. Someone should decide
   whether it is amended, scoped to file access specifically, or removed with a pointer.
2. **`decision-contract`: "Phase 1 records decisions without acting on them"** requires that the pipeline
   *"SHALL NOT invoke any enforcer"*, with a scenario asserting a BLOCK decision leaves the operation
   *"unimpeded"*. Enforcers have existed since M2 and run under `OPENSHIELD_ENFORCE`. The requirement is
   a Phase-1 statement that was never retired, and the D1 observe-only DEFAULT — which is still true and
   still important — is a different and weaker claim than this one.

Both were invisible while they were missing from the store. That is the argument for restoring them
unreconciled: a contradiction you can see is a decision waiting to be made, and one you cannot see is a
spec that quietly means nothing.
