// Package fitness holds the architectural fitness test (T-014).
//
// The project's central bet is that a fixed pipeline absorbs new capabilities as
// plugins and never requires editing the core. The test in this package is the
// executable form of that claim: it adds a connector, a stage and an enforcer
// defined ENTIRELY outside core — nowhere in the shipped tree — wires them
// through the public contracts, and flows an Event to a Decision. That it can be
// written using core's public API alone is the proof that a capability needs no
// core edit.
//
// READ THIS BEFORE TRUSTING A GREEN RESULT.
//
// This test is NECESSARY BUT NOT SUFFICIENT, and D26 records why with a worked
// example from T-004: letting Policy query the analytics store directly passes a
// diff-based fitness test with ZERO core changes while destroying the stage
// isolation the test exists to protect. Green CI here is not evidence the
// architecture held.
//
// What it guards:
//   - Adding a like-shaped capability needs no core edit (this package's test).
//   - Core depends on no concrete capability (scripts/check-capability-boundary.sh).
//   - A stage cannot reach a sibling except through the pipeline State, which
//     carries data and no handles (core: TestStageInterfaceExposesNoSiblingAccess).
//   - An enforcer sees only the Decision (core/enforcerisolation: a package that
//     must FAIL to compile, asserted in CI).
//
// What it CANNOT guard: a capability of a genuinely NEW shape may still need a
// small, identifiable core addition (D26) — that is expected, not a failure. And
// a novel end-run around the bus (a global, a shared singleton) is out of its
// reach; a reviewer remains necessary. The real test of the ten-year claim is a
// new-shape capability like peer-UEBA (docs/design-t004-peer-ueba.md), not a
// second connector isomorphic to the first.
package fitness
