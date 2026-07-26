## Why

PLAT-9 names it directly: *"a documented **deployment footprint** (this is a compose/systemd/single-Helm-
release product, not a 50-node cluster — state it, so operators can size it)"*, plus a DR runbook. The
roadmap's own criticism is that it "answers only packaging" — an operator can now install, verify a
release, stop enforcement and verify a restore, and still has nowhere that says **what this thing is, what
it costs to run, and what to do when it breaks**.

There is a specific reason to write it now rather than with the UI: everything it documents exists and has
been tested this cycle. A runbook written later is written from memory.

## What Changes

- **`docs/runbook.md`**: the deployment footprint (components, what each needs, what it is *not*), the
  operational procedures that now exist — verify a release, emergency-disable enforcement, verify a
  restore, read schema skew, change configuration — and the failure modes with their honest limits.
- **The component list is TESTED, not asserted.** A test cross-checks the documented components against
  `cmd/`, in both directions: a binary that ships undocumented fails, and a documented binary that no
  longer exists fails. A runbook naming components that do not exist is worse than none, because it is
  read under pressure.

## Capabilities

### Modified Capabilities
- `doc-consistency`: adds a drift guard binding the documented component set to the binaries that exist.

## Impact

- **New**: `docs/runbook.md`; a drift test in `internal/doccheck`.
- **No code change to the product**, no migration, no dependency.
- **Honest scope**: this documents what EXISTS. It does not add backup tooling, upgrade orchestration, or
  HA guidance beyond the leader lease that is already built. Sizing figures are stated as the shape of the
  deployment (single control plane, Postgres, NATS, N agents) rather than invented benchmark numbers —
  this project has not run a sizing exercise, and publishing figures it has not measured would be the kind
  of claim its review rounds exist to catch.
