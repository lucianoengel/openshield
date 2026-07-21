# Add the architectural fitness test (T-014)

## Why

The project's headline bet is that a fixed pipeline absorbs a decade of capabilities by adding
plugins, never editing the core. That claim is currently defended by discipline and by prose. It
needs an executable guard — and, just as importantly, an honest one, because T-004 already
proved the naive version of this test is gameable and D26 recorded it: "let Policy query the
analytics store directly passes CI with zero core diffs while destroying the stage isolation the
test exists to protect."

So this change is two things at once: a fitness test that fails when adding a capability would
require touching the core, and the explicit encoding of that test's known limits so a green
check is never mistaken for validation of the ten-year claim.

## What changes

**A fitness test that adds a capability entirely from outside core and proves it flows.** A
Connector (Event producer), a Stage, and an Enforcer are defined ONLY in the test package —
nowhere in the shipped tree — wired through the public core contracts, and an Event is carried
through the dispatcher to a Decision. Because these types exist nowhere in `internal/core`, the
test compiling and passing IS the proof that a capability can be added without editing the core.
This mirrors the existing `TestStageAddedWithoutEditingAnything`, extended to the connector and
enforcer contracts.

**A capability-direction CI check.** `internal/core` MUST NOT import `internal/connectors`,
`internal/enforcers`, `internal/classify`, `internal/policy`, or `internal/store` — the core
must not know about any concrete capability. Adding a capability therefore cannot require core to
reference it. Enforced by `go list -deps`, failing the build, alongside the existing
broker/database check.

**The gaming vectors, encoded as their own guards.** D26's worked example is that the diff-based
test is beaten by a stage reaching around the pipeline into shared state. This change adds guards
for the specific vectors:
- A capability MUST reach other stages only through the pipeline `State`, which carries data and
  no handles (the existing `TestStageInterfaceExposesNoSiblingAccess` is promoted into this
  suite and referenced as a fitness guard).
- An Enforcer MUST receive only the Decision — the compile-fail `enforcerisolation` guard is
  likewise gathered here.

**The honesty record, in the test and the docs.** The suite carries, in prose the reader cannot
miss and in a doc reference, the T-004 verdict: this test is necessary but not sufficient, green
CI is not validation of the architecture, and the real test of the claim is a capability of a
genuinely new shape (peer-UEBA), not a second connector isomorphic to the first.

## What this does NOT claim or cover

- **It does not prove the architecture holds.** It proves a specific, gameable property: that
  adding a like-shaped capability needs no core edit. A capability of a NEW shape may still need
  a small, identifiable core addition (D26) — and that is expected, not a failure. Green here is
  necessary, not sufficient.
- **It does not detect every way to reach around the bus.** It guards the vectors known today
  (sibling handles, enforcer inputs, import direction). A novel end-run — a global, a shared
  singleton, a package-level var — is out of its reach; a reviewer is still required, and the
  test says so rather than implying completeness.
- **It is not a performance or correctness test of any capability.** It checks architectural
  shape only.
- **It touches no runtime behaviour.** New test files and a CI check; no shipped code changes
  except doc/comment.

## Decisions

Depends on **D26** (the zero-core-change claim is narrowed; the fitness test is necessary but not
sufficient; T-004 is the worked example), the existing Stage/Enforcer/Transport/Ledger contracts,
and the isolation guards already in core.

No new decision — this implements the CI half of D26 and gathers the existing isolation guards
under one honestly-labelled suite.
