## Context

`core.Transport` has `PublishEvent/PublishClassification/PublishDecision/Close`, returning
`ErrUnreachable` when the control plane is down. `internal/transport/nats` implements it. core must
not import a broker (D24), so the queue lives in `internal/transport/queue` and wraps a Transport.

## Goals / Non-Goals

**Goals:**
- Durable, in-order, bounded store-and-forward wrapping any Transport, with the same interface.
- Survive process crash and restart; resume in order.
- Overflow drops oldest and fires a loud audit callback — never silent.

**Non-Goals:**
- Durability against disk loss / wipe; at-rest encryption; priority reordering; the ledger's own
  offline story (D31, separate).

## Decisions

### On-disk format: one atomically-written file per payload
A spool directory holds files named `<20-digit-seq>.msg`. Each file is `varint(kind) || protobytes`
where kind ∈ {1 Event, 2 Classification, 3 Decision}. Written via write-temp-then-rename, so a
crash mid-write leaves either a complete file or none — never a torn record. The next sequence is
`max(existing)+1`, recovered by scanning the directory on open, so restart resumes exactly.

Chosen over a single append-log because per-file atomic rename gives crash-safety for free and
FIFO drain/drop is just ordered iterate/unlink; the cost (an inode per queued item) is bounded by
the ceiling.

### QueueingTransport: enqueue-if-queued-or-unreachable
Each Publish* marshals the payload, then:
- if the queue is NON-EMPTY, enqueue (preserve FIFO — never overtake queued items);
- else try the inner transport; on `ErrUnreachable`, enqueue; on other error, return it; on
  success, done.
Enqueue always returns success to the caller, because the payload is now durably held — that is the
whole point. `Flush(ctx)` drains: iterate files in sequence order, publish each to the inner
transport, unlink on success, STOP on the first `ErrUnreachable` (the control plane went away
again; keep the rest). A non-unreachable publish error also stops, surfacing.

### Bound and overflow
`Max` is a payload-count ceiling. On enqueue, if size would exceed `Max`, unlink the OLDEST file
and call `OnOverflow(kind, seq)` BEFORE writing the new one. Dropping oldest keeps the freshest
activity, which an active investigation is most likely to need; the choice is stated because either
direction loses data and the caller deserves to know which. `OnOverflow` is where the agent writes
a high-severity audit entry — a drop that is not recorded is exactly the silent loss this exists to
prevent.

### The queue is storage-agnostic; QueueingTransport is the adapter
`Queue` (dir, Max, OnOverflow) does Enqueue/Drain/Len over `[]byte` records — pure disk logic,
tested directly. `QueueingTransport` maps the three Publish methods onto kinds and wires the inner
transport. This keeps the crash-safety/bound logic testable without a transport and the transport
adaptation trivial.

## Risks / Trade-offs

- **Enqueue returns success though delivery has not happened.** Intended: durably-held is the
  success the caller needs; actual delivery is Flush's job. The alternative (return the error) puts
  the retry burden back on every caller, which is what the queue exists to remove. Delivery failure
  surfaces via Flush and via the overflow event.
- **Drop-oldest loses the start of a session on sustained overflow.** Stated; the bound is
  non-negotiable (disk DoS otherwise), and loud beats silent.
- **An inode per payload.** Bounded by Max; fine for the volumes an endpoint produces. A segmented
  log is the optimisation if Max ever needs to be huge.
- **FIFO, not priority.** A flood of routine Events can delay a Decision behind them. Noted; priority
  is a later refinement, not silently assumed.
