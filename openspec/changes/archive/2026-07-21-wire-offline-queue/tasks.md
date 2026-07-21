# Tasks — wire the durable offline queue into the signed path

## 1. Store-or-forward on the signed publisher

- [x] 1.1 `SignedPublisher` gains an optional `Spool` (satisfied by *queue.Queue), store-or-send (enqueue when unreachable or spool non-empty, preserving FIFO), and `Flush`; injectable send/connected seams.

## 2. Wire the fleet agent

- [x] 2.1 `cmd/openshield-fleet-agent`: open a bounded `queue.Queue` at `OPENSHIELD_QUEUE_DIR` (when set), attach it, `Flush` each tick; a loud log on overflow eviction.

## 3. Tests (guards, each mutation-tested)

- [x] 3.1 **Test**: with a spool and the connection DOWN, published messages are ENQUEUED (none lost); after the connection recovers, `Flush` delivers them IN ORDER, byte-for-byte (sequence + signature intact).
- [x] 3.2 **Test**: FIFO is preserved — while the spool is non-empty a new message goes behind the queued ones, not ahead, even though the connection is up.
- [x] 3.3 **Test**: a bounded queue overflow fires the loud callback (no silent loss).

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D67: the durable offline queue is wired into the signed path + fleet agent — signed telemetry is spooled on an outage and re-sent in order; bounded, overflow loud (D31); realizes D1's offline-capable principle.
- [x] 4.2 `openspec validate wire-offline-queue --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| storeOrSend always sends direct (never spools on outage) | `TestSpoolStoreAndForward` (loss on outage) |
| storeOrSend ignores the backlog when connected | `TestSpoolFIFOWhenConnected` (races ahead) |
| overflow drops silently | `TestSpoolOverflowIsLoud` (via the queue's callback) |

The durable offline queue is wired into the signed path and the fleet agent:
signed telemetry is spooled when the control plane is unreachable and re-sent in
order on reconnect (byte-for-byte — sequence + signature intact), FIFO preserved,
bounded, overflow loud (D31). Realizes D1's offline-capable principle — the D40
mechanism now has a production caller.
