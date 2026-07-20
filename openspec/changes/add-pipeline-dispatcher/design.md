## Context

T-003 delivered contracts and nothing that moves data through them. This change builds the
mechanism that makes the pipeline real, and it must resolve an ambiguity the brief left open:
the brief names NATS as "the message bus" and says components communicate exclusively through
events, which — read literally on the endpoint — would put a broker inside the fanotify
permission window.

T-002 measured that window's budget: 1-3µs typical, 532µs worst case, while a real process sits
in `TASK_UNINTERRUPTIBLE`. A broker round trip does not fit. This is the measurement that
decides the architecture, which is why T-002 ran before this change rather than after.

## Goals / Non-Goals

**Goals:**
- An in-process stage dispatcher where stages know nothing about each other.
- A transport interface for the agent↔control-plane boundary, with NATS behind it.
- Deterministic replay of a recorded Event to the same Decision.
- CI enforcement that `internal/core` never imports a broker.

**Non-Goals:**
- Any real stage (classification, policy, audit are their own tickets).
- The control plane (T-023) or the offline queue (T-024).
- Distributed or cross-host stage execution. The endpoint pipeline is in-process by
  measurement, not by convenience.

## Decisions

### Two mechanisms, not one "event bus"

**Chosen:** an in-process synchronous dispatcher on the endpoint, plus an asynchronous NATS
transport to the control plane. Both are "the event bus" in the brief's language; only the
second is NATS.

Conflating them is the failure this design most needs to avoid. A broker-mediated endpoint
pipeline would put network latency and broker availability inside a syscall that has a real
process blocked behind it — converting a network partition into a hung machine. It would also
contradict local-first evaluation (D1): classification and policy run on the endpoint precisely
so that a decision does not depend on reachability.

**Rejected:** NATS in-process (embedded server) as a uniform abstraction. Uniformity is
appealing and the cost is a broker in the permission path for no benefit — the endpoint has
exactly one consumer of each stage's output.

### Stages return an outcome, not a mutated context

**Chosen:** `Stage.Run(ctx, *State) (Outcome, error)` where `Outcome` is `Continue`, `Decided`
or `Failed`.

**Why not a middleware chain (`next(ctx)`)?** Because middleware composes by each layer holding
a reference to the next, which is exactly the coupling the architecture forbids — a stage that
can call `next` can wrap, skip or reorder its neighbours. An explicit outcome returned to a
dispatcher that owns ordering keeps stages ignorant of each other.

**Cost:** the dispatcher owns control flow, so a stage cannot do cleanup "after the rest of the
pipeline". Accepted; nothing in the roadmap needs that, and the coupling it would introduce is
the thing being prevented.

### Deadlines belong to the dispatcher, not the stage

**Chosen:** the dispatcher applies a per-stage deadline; stages receive a context and are
expected to honour it.

A stage that sets its own deadline can set it to infinity. Since an unbounded stage is the
mechanism that hangs a machine — the real risk T-002 isolated, as distinct from the GC pause it
exonerated — the budget must be owned by the component that cannot be replaced by a plugin.

**Risk:** a stage that ignores its context still runs long. Go cannot preempt an uncooperative
function. → The dispatcher enforces the deadline on *its own* wait, abandoning the Event and
emitting a timeout outcome; the goroutine may outlive it. That is a leak under pathological
stages and is the honest limit of this design. Documented rather than hidden, and it is why
T-011's watchdog (which answers the kernel regardless) is a separate mechanism rather than a
consequence of this one.

### Transport is an interface in core, implemented outside it

**Chosen:** `core.Transport` interface; `internal/transport/nats` implements it; a CI check
asserts `internal/core` has no broker in its dependency graph.

This is the same pattern as enforcer isolation: state the boundary in the type system, then
prove it with a check that fails the build. A comment saying "core should not import NATS" is
not a boundary.

### Replay compares on an explicit field list

**Chosen:** replay equality compares action, confidence, reason, policy ID and version, with
non-deterministic fields (decision ID, timestamps) excluded by an **explicit** list.

**Why not compare everything except a denylist computed at runtime?** Because a new
non-deterministic field would then be silently excluded and replay would quietly weaken. An
explicit list means adding such a field breaks the test and forces the question.

## Risks / Trade-offs

- **An uncooperative stage cannot be preempted.** → Deadline governs the dispatcher's wait, not
  the goroutine; leak is possible and documented. T-011's watchdog is the independent mechanism
  that protects the kernel-facing path.
- **In-process dispatch limits future distribution.** → Accepted deliberately. If cross-host
  execution is ever needed it is a new design, not a flag. Pretending otherwise now would put a
  broker in the syscall path today for a capability nobody has asked for.
- **The transport interface may not survive contact with T-024's durable queue.** → The seam is
  shaped for it, but store-and-forward has requirements (ordering, bounded overflow, replay from
  disk) that this change does not implement. If T-024 forces an interface change, that is
  expected and cheap now.
- **Trivial stages could make the wiring test vacuous.** → The stage-registration test registers
  a stage defined in the test package alone, so it cannot pass by virtue of a stage the core
  already knows about.
- **"Every component communicates through events" is now partly false.** The endpoint pipeline
  calls functions. → Stated plainly here and in the proposal rather than left as a discrepancy
  between the brief and the code. The brief's principle survives at the boundary that matters:
  connectors publish events, and nothing bypasses the dispatcher.

## Migration Plan

Nothing consumes these types yet. Order: stage/dispatcher interfaces → registry → deadline and
error handling → transport interface → NATS implementation → replay → CI import check.

## Open Questions

1. **Per-stage deadline values.** Placeholder budgets until T-006 measures the real classifier;
   the mechanism matters now, the numbers do not.
2. **Does the audit stage belong in the dispatcher or after it?** T-009 decides. Leaning after,
   so that audit records the pipeline's outcome rather than participating in it.
3. **JetStream stream and subject naming.** Deferred to T-023, which owns the control-plane side
   and will have to live with the choice.
