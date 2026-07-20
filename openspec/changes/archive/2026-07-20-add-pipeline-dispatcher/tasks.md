## 1. Stage and dispatcher interfaces

- [x] 1.1 Define `Stage`, `State` and `Outcome` (`Continue` / `Decided` / `Failed`) in
      `internal/core`. Stages return an outcome; they do not receive a `next` handle
- [x] 1.2 Define the stage `Registry` — ordered registration, no lookup-by-name that would let
      one stage find another
- [x] 1.3 **Test**: the stage interface exposes no registry, dispatcher or sibling handle.
      Asserted by reflection over the interface's method set, not by reading it

## 2. Dispatcher execution

- [x] 2.1 Implement `Dispatcher.Dispatch(ctx, *Event) (*Decision, error)` running stages in
      registration order, single pass
- [x] 2.2 **Test**: a stage defined *in the test package alone* can be registered and runs in
      order, with no edit to any other stage. This is the architectural claim in executable
      form — the test must not use a stage core already knows about, or it passes vacuously
- [x] 2.3 **Test**: dispatching the same Event twice through an identical pipeline yields equal
      Decisions (action, confidence, reason, policy identity)
- [x] 2.4 Refuse re-entry: a stage attempting to dispatch from inside the pipeline is rejected
      rather than recursing. **Test**: assert the specific error, and that no stack growth occurs

## 3. Failure and deadline handling

- [x] 3.1 A stage returning an error produces a terminal outcome naming the failed stage; the
      Event is never silently dropped. **Test**: exactly one audit record for the failed Event
- [x] 3.2 Apply a per-stage context deadline owned by the dispatcher, not the stage (a stage
      that sets its own deadline can set it to infinity)
- [x] 3.3 On expiry, abandon that Event's pipeline and emit a **high-severity** timeout outcome.
      **Test**: assert the outcome is severity-marked, not merely present — a quiet timeout is
      indistinguishable from a clean allow
- [x] 3.4 Count timeouts separately from ordinary outcomes so a rising rate is its own signal
      (D17). **Test**: the counter increments only on timeout
- [x] 3.5 Document in code that an uncooperative stage's goroutine may outlive the deadline —
      Go cannot preempt it. This is the honest limit of the design and the reason T-011's
      watchdog is an independent mechanism

## 4. Transport interface

- [x] 4.1 Define `core.Transport` accepting `Event`, `ClassificationSummary` and `Decision` —
      and deliberately having **no** method accepting `LocalClassification`
- [x] 4.2 **Negative compile test**: publishing a `LocalClassification` must fail to compile,
      asserting the specific compiler error (same mechanism as enforcer isolation, same reason —
      a build that fails for an unrelated typo would pass vacuously)
- [x] 4.3 Publish returns an explicit error on unreachable control plane; never discards, never
      blocks. **Test**: publish returns faster than the stage deadline when the endpoint is down
- [x] 4.4 **Test**: a test-double transport substitutes cleanly and no caller references a NATS
      type

## 5. NATS implementation

- [x] 5.1 Implement `internal/transport/nats` against the interface
- [x] 5.2 **CI import check**: `internal/core`'s dependency graph contains no NATS client and no
      network transport package, via `go list -deps`. Fails the build, does not warn
- [ ] 5.3 Integration test against a real NATS instance, skipped when unavailable — and the skip
      must be **loud** in CI output, so an always-skipped integration test is not mistaken for a
      passing one

## 6. Replay

- [x] 6.1 Implement replay: given a recorded Event and pipeline configuration, re-run and
      produce a Decision
- [x] 6.2 **Test**: replayed Decision equals the recorded one, comparing an **explicit** field
      list (action, confidence, reason, policy ID, version). Non-deterministic fields are
      excluded by name, so adding a new one breaks the test rather than silently weakening it

## 7. Wiring and docs

- [x] 7.1 Add the import check and negative-compile test to `.github/workflows/ci.yml`
- [x] 7.2 Record in `docs/decisions.md` that the endpoint pipeline is in-process and NATS is the
      agent↔control-plane boundary only — with the T-002 measurement as the reason. This is a
      new decision; it establishes rather than depends on one
- [x] 7.3 Mark T-022 done in `docs/plan-phase1.md`; sync specs; archive the change

## Verification performed

Guards mutation-tested, since a test that never fails is indistinguishable from
no test:

| mutation | caught by |
|---|---|
| timeout marked `SeverityInfo` instead of `High` | `TestSlowStageTimesOutLoudly` |
| timeouts counted as ordinary failures | `TestTimeoutsCountedSeparatelyFromFailures` |
| failed Event dropped without reporting | `TestFailingStageIsAuditedExactlyOnce` |
| `internal/core` importing `nats.go` | `scripts/check-core-deps.sh` (verified by adding the import, then removing it) |
| publishing a `LocalClassification` | compiler, asserted on the specific error |

**5.3 not done:** the NATS integration test against a live broker is not
written. There is no NATS instance here, and a test that always skips is worse
than no test — it shows green while proving nothing. Deferred to T-023, which
builds the control plane and will have a broker to test against.
