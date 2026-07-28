## Why

D322 restored 170 requirements to the spec store without reconciling them, which was the right call and
which immediately surfaced two requirements the product has outgrown:

- **`enforcement`** requires that *"inline blocking within the permission window is not provided"* and
  that it *"stays deferred because the pipeline cannot complete in the permission window"*. HIPS-3 denies
  an exec inside that window, NIPS-1 drops a flow at L4, the gateway refuses an upload before forwarding,
  the print filter refuses a job before it prints, and the USB enforcer deauthorizes a device.
- **`decision-contract`** requires that the pipeline *"SHALL NOT invoke any enforcer"*, with a scenario
  asserting a BLOCK decision leaves the operation *"unimpeded"*. Enforcers have existed since M2.

Leaving these is worse than it looks. They are not merely stale — they are the two requirements that
state the project's central honesty commitment (D16: detection, not prevention), so a reader checking
whether the product overclaims finds a spec claiming *less* than the product does. A spec that
understates is as useless for that purpose as one that overstates: neither can be used to check anything.

## What Changes

Both are replaced rather than edited, because in each case the NAME is now the wrong claim.

- **`enforcement`**: the old requirement is REMOVED and replaced by one that draws the line where it
  actually falls. Investigating this found that the original is **still true for file access** — nothing
  in the shipped product answers `FAN_OPEN_PERM`, so a file open is not blocked — and false for exec,
  network, print, clipboard and USB. The replacement says exactly that, per domain, and keeps the
  anti-overclaim rule intact by tying each claim to a mechanism that exists.
- **`decision-contract`**: the Phase-1 requirement is REMOVED and replaced by the enduring rule it was a
  temporary instance of — **recording is unconditional, acting is opt-in and off by default**. That is
  still true, still load-bearing (D1), and unlike the original it does not expire.
- **Delta tooling learns `REMOVED` and `RENAMED`.** D322's audit script, restore script and doccheck
  guard understand `ADDED` and `MODIFIED` and deliberately REFUSE anything else rather than skip it. This
  change is the first to remove a requirement, so the guard must stop demanding a removed requirement's
  presence — otherwise removing one is impossible without disabling the guard. The refusal did its job:
  it forced the tools to be taught rather than silently dropping the section.

**Not in scope:** wiring the file-open prefilter. `internal/agent/prefilter` implements the two-tier
design and has no caller in `cmd/`; that is recorded as a finding, not fixed here, because it needs a new
privileged agent mode and a VM-gated kernel test.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `enforcement`: the prevention claim is scoped per domain instead of denied outright.
- `decision-contract`: the Phase-1 "never enforces" rule is replaced by the durable opt-in rule.
- `spec-store-integrity`: the integrity check must honour removal and renaming, not only addition.

## Impact

- `openspec/specs/enforcement/spec.md`, `openspec/specs/decision-contract/spec.md` — one requirement each,
  removed and replaced.
- `scripts/spec-store-audit.py`, `scripts/spec-store-restore.py`, `internal/doccheck` — handle `REMOVED`
  and `RENAMED`.
- No runtime code. No behaviour changes: this describes what the product already does.
- **Risk:** getting the per-domain line wrong would reintroduce exactly the overclaim D16 forbids, so
  every claim in the replacement requirement names the mechanism that implements it and the scenario that
  proves it.
