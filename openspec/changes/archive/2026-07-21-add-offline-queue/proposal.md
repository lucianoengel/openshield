# Add the offline store-and-forward queue (T-024)

## Why

"Offline-capable" is a stated core principle (D1: local-first, the agent must decide without the
network) and nothing implements it for the agent→control-plane path. Today `Transport.Publish*`
returns `ErrUnreachable`/`ErrPayloadDropped` when the control plane is down — an honest error, but
an error the caller has nowhere to put. A laptop that wakes on a train produces Events, a
classification, a Decision, and every one is lost. For a product whose only honest claim is a
trail of what it saw, silently losing that trail on a network blip is the failure the whole system
exists to prevent (this is exactly the gap D31 named).

## What changes

**A durable store-and-forward queue that wraps any `Transport`.** `QueueingTransport` implements
`core.Transport`, so callers are unchanged (the seam was shaped for this). When the inner transport
is reachable and the queue is empty, it publishes directly. When the inner transport is unreachable
— OR the queue already holds anything — it persists the payload to disk and returns success to the
caller, because the payload IS now safely held. `Flush` drains the disk queue to the inner
transport in order when the control plane returns.

**Durable across restart, and in order.** Each queued payload is one atomically-written file named
by a monotonic sequence, so a crash mid-write cannot corrupt the queue and restart resumes exactly
where it left off. Draining is strict FIFO: while anything is queued, new payloads go behind it, so
the control plane receives events in the order the agent produced them — an out-of-order audit
trail is a broken one.

**Bounded, with overflow as a LOUD event, never a silent drop.** The queue has a maximum size.
When a new payload would exceed it, the queue drops the OLDEST and invokes an overflow callback —
overflow is itself recorded as a high-severity audit event (D17-style: a silent drop is
indistinguishable from nothing happening). Dropping oldest, not newest, is a deliberate, stated
choice: a bounded evidence queue that has overflowed has already lost its guarantee, and the most
recent activity is the most likely to matter to an active investigation.

## What this does NOT claim or cover

- **It does not make delivery guaranteed against disk loss or a wiped machine.** It survives a
  process crash and a reboot; it does not survive `rm -rf` or a dead disk. Durable-to-disk, not
  durable-to-anything.
- **It does not remove the bound.** A queue that grows without limit is a disk-exhaustion DoS. The
  bound is real, so sustained offline operation past the ceiling DROPS oldest data — loudly. The
  honest guarantee is "no silent loss", not "no loss".
- **It is not the audit ledger's durability.** The ledger requires a reachable database and has no
  offline story of its own (D31); that is a separate gap. This queue is the agent→control-plane
  telemetry path, not the local system-of-record.
- **It does not reorder to prioritise.** Strict FIFO. A future priority scheme (get Decisions out
  before routine Events) is not built; stated so the FIFO choice is deliberate.
- **It does not encrypt the queued payloads at rest.** They are the same payloads the transport
  would send; at-rest encryption of the spool is a deployment/hardening concern, noted not solved.

## Decisions

Depends on **D1** (offline-capable / local-first), **D24** (the transport is the agent↔control-plane
boundary; core must not import a broker — the queue lives outside core), **D31** (the offline gap
this addresses for telemetry), and **D17** (a bypass/loss must be loud).

Establishes a new decision: **the agent store-and-forwards telemetry through a bounded, durable,
FIFO disk queue; overflow drops OLDEST and is a high-severity audit event — no silent loss, but a
bounded guarantee.**
