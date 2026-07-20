## Why

The Event Bus is described in the project brief as "the backbone of the platform", and until the
roadmap was audited it had **no ticket at all** — the plan was decomposed from contested
decisions, and nobody had argued about the backbone. It is the piece that makes the pipeline a
pipeline rather than four types that happen to exist.

Without it, T-003's contracts are inert: there is nothing that takes an Event, moves it through
Classification and Policy, produces a Decision, and lands it in Audit.

Implements ticket T-022.

## A distinction this change has to settle

The brief says "every component communicates exclusively through events" and names NATS
JetStream as the message bus. Taken literally on the endpoint, that is wrong, and the reason is
measured rather than aesthetic.

The fanotify responder answers permission events while a real process sits blocked in
`TASK_UNINTERRUPTIBLE`. T-002 measured the Go-side budget at 1-3µs typical and 532µs worst case.
A network round trip through a broker does not fit in that budget, and "the server coordinates,
it does not continuously control" (D1, and the local-first principle) says it should not have to.

So there are **two distinct mechanisms**, and conflating them is how this design goes wrong:

1. **The in-process stage dispatcher** on the endpoint — synchronous, in-memory, no broker.
   Event → Classification → Policy → Decision. This is what "the pipeline" means at runtime.
2. **The transport bus** between agent and control plane — NATS JetStream, asynchronous, for
   telemetry, audit records and replay.

Both are "the event bus" in the brief's sense. Only the second one is NATS.

## What Changes

- New `internal/core` dispatcher: an ordered set of registered stages, each taking the pipeline
  context and returning either a continuation or a terminal Decision.
- A stage registry, so adding a Classifier or a Policy source does not edit any other stage.
- **BREAKING to nothing** — there are no existing consumers.
- Transport publisher/subscriber interfaces with a NATS JetStream implementation, kept behind an
  interface so that `internal/core` does not import NATS. Core must not depend on a broker.
- Replay: given the recorded stream for an Event, re-running the pipeline reproduces the same
  Decision.

## Capabilities

### New Capabilities
- `pipeline-dispatcher`: stage registration, ordering, execution, error and timeout handling,
  and the guarantee that stages do not know about each other.
- `event-transport`: the agent↔control-plane boundary — publishing, delivery guarantees, and
  what happens when the control plane is unreachable.

### Modified Capabilities
None. `event-contract`, `decision-contract` and `classification-contract` are consumed unchanged
— which is itself a test of whether T-003 got them right.

## Impact

- **Code:** `internal/core` gains the dispatcher and stage interfaces. A new
  `internal/transport` holds the NATS implementation. `internal/agent` will wire them together
  in T-006.
- **Dependencies:** adds `nats.go`, confined to `internal/transport`. A CI import check should
  assert `internal/core` never imports it.
- **Downstream:** T-006 (agent), T-007 (classifier), T-008 (policy), T-009 (audit) all register
  as stages. T-024 (offline queue) sits behind the transport interface.

## What this change does NOT do

- **Does not implement any stage.** Classification, policy and audit are their own tickets. This
  change ships the dispatcher plus trivial stages sufficient to prove the wiring.
- **Does not build the control plane.** That is T-023. The transport interface is defined and
  the NATS implementation exists, but there is nothing on the other end yet.
- **Does not implement the offline queue.** T-024. The transport interface is shaped so a
  store-and-forward implementation can slot in without changing callers, but "offline-capable"
  is not delivered here and must not be claimed.
- **Does not make the pipeline distributed.** The endpoint pipeline is in-process by design, for
  the latency reason above. If a future capability needs cross-host stage execution, that is a
  new design, not a configuration flag.
- **Does not address ordering across agents.** Sequence numbers are per agent (T-003); a global
  ordering across a fleet is not defined and is not needed by anything in Phase 1.
