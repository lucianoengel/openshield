## Context

Core NATS is fire-and-forget: a subscription buffers pending messages client-side, and when
that buffer overflows the library drops the oldest and (only if asked) notifies via the
async error handler. Without the handler, the drop is silent.

## Goals / Non-Goals

**Goals:** count + log receive-side drops (SlowConsumer); make overflow deterministic.

**Non-Goals:** JetStream durability (PLAT-2); agent backpressure.

## Decisions

**ErrorHandler + explicit pending limits.** The connection installs an async ErrorHandler
that increments `DroppedMessages` and logs the subject + error. Each subscription sets
explicit pending limits so overflow behaviour is deterministic (bounded, and it fires the
handler) rather than relying on the library default. Together: a slow consumer's loss is
counted and loud, matching the send side's spool/gap discipline.

**Observe now, durability later.** This does not PREVENT loss under sustained overload — it
makes loss OBSERVABLE, which is the invariant ("no silent loss"). JetStream durable
consumers with ack (PLAT-2) remove the drop window entirely; this stopgap is worth doing
regardless, as the audit notes.

## Risks / Trade-offs

- **Bounded queue can still drop under sustained overload** — but now visibly. The real
  durability fix is PLAT-2; this closes the SILENT part of the bug.
- **The counter is process-local** (like the other counters); persisting/metrics is PLAT-4.
