## Context

`queue.Queue` (D40) is a durable, bounded, FIFO spool of opaque `[]byte` records
(Enqueue/Drain/Len, crash-safe via temp+rename). The SIGNED path forms a signed
envelope with a monotonic persisted sequence (D66) and publishes the raw bytes
with core NATS `conn.Publish` (at-most-once). Nothing spools those bytes on an
outage, and the fleet agent discards publish errors.

## Goals / Non-Goals

**Goals:**
- No SILENT loss of signed telemetry during a control-plane outage: spool and
  re-send on reconnect, in order.
- Re-sent messages verify identically (raw bytes carry seq + signature).
- Testable without a live broker.

**Non-Goals:**
- Unbounded durability — the spool is bounded; overflow drops oldest LOUDLY (D31).
- Exactly-once / gap-free — late delivery is a gap (accepted, D50).
- Changing the queue package or the wire format.

## Decisions

**Store the raw signed envelope, re-send verbatim.** The envelope bytes already
contain the sequence and signature, so a spooled message re-sent later verifies
exactly as if sent live — no re-signing, no re-sequencing. This is why the generic
`queue.Queue` (opaque bytes) fits the signed path directly, without the
proto-re-marshalling `QueueingTransport` (which is for the unsigned transport).

**Store-or-forward with FIFO preservation.** `storeOrSend`: if a spool is
attached and either it is non-empty OR the connection is down, ENQUEUE (so a
recovered connection does not let a new message race ahead of queued ones);
otherwise publish directly, and on a send failure enqueue (an outage mid-send
must not lose the payload). `Flush` drains in order, stopping at the first failure
and keeping the tail.

**Injectable seams.** `send func([]byte) error` and `connected func() bool` default
to the live `*nats.Conn` (unreachable → `core.ErrUnreachable` so storeOrSend
enqueues) but are overridable, so the store-or-forward and FIFO logic are unit-
tested deterministically without standing up NATS.

**The agent flushes on its tick and logs overflow loudly.** The fleet agent opens
the queue at `OPENSHIELD_QUEUE_DIR` (bounded by a max), attaches it, and calls
`Flush` each heartbeat tick — draining whatever accumulated during an outage. The
queue's `onOverflow` fires a high-severity log: a drop that is not recorded is the
silent loss this exists to prevent (D31).

## Risks / Trade-offs

- **Bounded spool drops oldest on overflow.** A long outage past the ceiling
  loses the OLDEST records — loudly (a logged eviction), keeping the freshest an
  active investigation most needs. "No silent loss," not "no loss" (D31).
- **Gaps on late delivery.** A message spooled and delivered later arrives out of
  real-time order relative to a restart's new sequence; the control plane records
  a gap (D50). Correct: an outage IS a suppression window.
- **Disk usage while spooled.** The spool consumes disk under `OPENSHIELD_QUEUE_DIR`
  up to its ceiling; sized by the operator. Documented.
