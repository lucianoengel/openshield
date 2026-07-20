## Why

**This proposal documents work already implemented.** That is itself the problem it records.

T-004, T-030 and T-006 were built without OpenSpec changes. The consequence was immediate and
exactly the failure this project keeps fighting: `decision-contract/spec.md` does not mention
`context_version` although the code has it, `pipeline-dispatcher/spec.md` does not mention
`State.Context` although the code has it, and the agent process boundary — the most
security-critical capability in the codebase, with a durable IPC contract — has no spec at all.

The cause was momentum. Asked to keep moving, work optimised for visible progress over the
process that keeps specs true. `CONTRIBUTING.md` already said capability work gets a change;
"continue" was treated as an exemption. It is not.

This change brings the specs in line with what shipped, and adds the missing capability spec.

## What Changes

- **New spec** `agent-process-boundary`: the two-binary privilege split, the IPC contract, and
  what may not cross the boundary. Implemented in `internal/agent/*` and `cmd/openshield-worker`.
- **MODIFIED** `decision-contract`: `Decision` carries `context_version` (D27).
- **MODIFIED** `pipeline-dispatcher`: `State` carries a nil-able `Context` (D28), and State
  fields must be inert data rather than handles.

No code changes. The code is correct; the specs were behind it.

## Capabilities

### New Capabilities
- `agent-process-boundary`: the privileged/unprivileged split, the IPC framing contract, and the
  rule that attacker-controlled content never reaches the privileged process.

### Modified Capabilities
- `decision-contract`: gains `context_version`, required for replay determinism.
- `pipeline-dispatcher`: gains the enrichment Context seam and the inert-data rule for State.

## Impact

Documentation only. `openspec/specs/` becomes true again.

## What this change does NOT do

- **Does not claim the process was followed.** It records that it was not, so the gap is visible
  in history rather than silently closed.
- **Does not implement the Context subsystem.** Only the seam exists (T-030); nothing computes a
  Context.
- **Does not add a mechanism preventing recurrence.** The honest guard here is process, and this
  project's own doctrine says process rots. The mitigation is that changes stay small enough
  that skipping one is never worth it — not a meta-check that would itself need maintaining.
