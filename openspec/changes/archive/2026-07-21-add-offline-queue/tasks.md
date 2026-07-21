## 1. The durable queue

- [x] 1.1 `internal/transport/queue`: `Queue{dir, Max, OnOverflow}` over `[]byte` records. Files
      `<20-digit-seq>.msg`, written temp-then-rename (atomic); next seq = max(existing)+1 on open
- [x] 1.2 `Enqueue(rec)`: if at Max, unlink oldest + call OnOverflow, then write; `Len()`
- [x] 1.3 `Drain(fn func([]byte) error)`: iterate in seq order, call fn, unlink on success, STOP on
      the first error (keep the rest)

## 2. QueueingTransport

- [x] 2.1 `QueueingTransport` wrapping an inner `core.Transport` + a `Queue`; kind tags for Event
      (1), Classification (2), Decision (3): `varint(kind) || protobytes`
- [x] 2.2 Publish*: if Len>0 enqueue; else try inner, on ErrUnreachable enqueue, else return; enqueue
      returns success (payload durably held)
- [x] 2.3 `Flush(ctx)`: Drain, decoding each record and publishing to the inner transport

## 3. Tests

- [x] 3.1 **Test**: offline → publish several → online → Flush; all delivered in FIFO order.
      `TestOfflineThenFlushInOrder`
- [x] 3.2 **Test**: reopen the spool dir; queued payloads survive and drain in order. `TestSurvivesRestart`
- [x] 3.3 **Test**: fill past Max; oldest dropped, OnOverflow fired, newest retained. `TestOverflowDropsOldestLoudly`
- [x] 3.4 **Test**: online + empty queue → direct publish, no file written. `TestOnlineEmptyGoesDirect`
- [x] 3.5 **Test**: once queued, a later payload queues behind (FIFO preserved even if the inner
      transport recovers mid-stream). `TestQueuedPayloadsAreNotOvertaken`
- [x] 3.6 **Test**: Flush stops on ErrUnreachable and keeps the undelivered tail. `TestFlushStopsWhenUnreachableAgain`

## 4. Docs

- [x] 4.1 Note in `docs/decisions.md` (new D-number): bounded durable FIFO store-and-forward;
      overflow drops oldest and is a high-severity audit event; no silent loss, bounded guarantee
- [x] 4.2 Mark T-024 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| overflow drops newest / no callback | `TestOverflowDropsOldestLoudly` |
| Drain continues past an error (drop the failed record) | `TestFlushStopsWhenUnreachableAgain` |
| a payload overtakes a non-empty queue | `TestQueuedPayloadsAreNotOvertaken` |

Offline→online delivers everything in FIFO order (`TestOfflineThenFlushInOrder`);
the spool survives a restart via a fresh queue over the same directory
(`TestSurvivesRestart`); a direct online publish writes no file
(`TestOnlineEmptyGoesDirect`). Each payload is one atomically-renamed file so a
torn write cannot corrupt the queue. The acceptance scenario (kill control plane
→ generate → restart → all arrive in order; fill past the ceiling → documented
overflow) is covered by these tests against a toggleable fake transport. Removed
the CI still-to-come note for T-024.
