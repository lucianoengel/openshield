# PRIV-1 · The exclusion list was a type with no caller

## Why

`openspec/specs/privacy-features/spec.md` carries this requirement:

> ### Requirement: An excluded subject produces no event
>
> The producing path MUST NOT emit an event for a subject matching a configured exclusion (a
> personal-folder path, a break-time window) — exclusion is at the source, before classification, so
> no personal data about it is created.

`internal/core/exclusion.go` implements the predicate. `ExclusionSet.Excluded(path, at)` is correct,
its tests pass, and **nothing in the shipped tree ever calls it.** Not the engine, not any producer,
not any binary in `cmd/`. There is no configuration key that would build one. `git grep` for
`ExclusionSet` outside its own file and its own test returns nothing.

The acceptance scenario is the tell:

> - **AND** a test asserts the exclusion predicate and that an excluded subject yields no event

The predicate is asserted. The word doing the work is **configured** — and there has never been a way
to configure one.

This is the worst kind of unwired feature, because of what it is:

- `docs/dpia-template.md` asks the deployer to record *"Exclusions configured: personal folders,
  break-time windows"*. That field cannot be truthfully filled in.
- `docs/plan-phase1.md` T-013 lists *"exclusion lists as a first-class policy primitive"* with the
  acceptance criterion *"an excluded path produces no event"*.
- It is the control a deployer would present to a works council, and rely on legally.

The clipboard's `OPENSHIELD_CLIPBOARD_EXCLUDE` is a **different, narrower** mechanism — exclusion by
source application, which is wired and works. It does not cover personal folders or break time, and
its existence is probably why the gap went unnoticed.

## What changes

1. **The engine applies the exclusion, before classification.** `Engine.Process` is the one chokepoint
   every endpoint producer goes through, and it sits before `Dispatch` — so an excluded subject's
   content is never read, never classified, never decided, never ledgered and never projected. That is
   the spec's claim, at the only place that can honestly make it.

2. **`OPENSHIELD_EXCLUDE_PATHS` and `OPENSHIELD_EXCLUDE_WINDOWS`**, both validated at load. A window
   that does not parse, or that ends before it starts, is refused loudly — a silently-dropped
   exclusion means the operator believes personal folders are unobserved while they are being read.

3. **An exclusion never suppresses an enforcement decision.** This is derived from the spec's own
   sentence — *"The operator owns the exclusion list, so it is a privacy control, not a user-invokable
   DLP evasion"*. An exclusion applied to an exec-permission event would not merely stop observation;
   it would change the outcome to ALLOW, making a break-time window a nightly interval in which
   anything runs. That is a user-reachable evasion, which is exactly what the requirement says an
   exclusion must not be.

4. **The path-less identity forms are counted and named, not silently observed.** Two of the three
   fanotify subject identities carry no path (`docs/spike-t005-fanotify.md`), and a path exclusion
   cannot be evaluated against them. The event is observed — the safe direction for detection — and
   the fact that an exclusion *could not be applied* is counted and reported. A privacy control with a
   silent blind spot is a false statement to a works council (D31: a gap must never be silent).

## Impact

- **Behaviour:** with no exclusion configured, nothing changes at all.
- **No schema, no proto, no migration.** The type already exists and is already correct.
- **Deliberately not in scope:** per-user or per-group exclusions (there is no directory integration,
  and pseudonymous subjects cannot be mapped to people at the endpoint); exclusion of network/gateway
  events (a flow has no personal-folder path, and the gateway is a different trust domain);
  exclusions distributed from the control plane (a pushed exclusion is a pushed blind spot, and that
  needs the signed-control trust review, not an env var).
