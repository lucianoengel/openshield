# DLP-2 · One job, two pipeline runs, one copy of the evidence

## Why

`printDecider` and the clipboard mediator each do this:

```go
store.Put(ev.GetEventId(), content)   // register the bytes for the classifier
select { case events <- ev: ... }     // hand the event to the OBSERVATION loop
dec, err := eng.Process(ctx, ev)      // and run the pipeline HERE for the verdict
```

`events` is the engine's main channel, drained by `processOne`. So **one print job, and one mediated
clipboard copy, runs the whole pipeline twice** — two classifications, two decisions, two ledger
entries, two telemetry projections, two unified alerts.

That is wasteful. What makes it a defect is `ContentStore.Resolve`, which **deletes on read**:

```go
b, ok := s.items[eventID]
if ok { delete(s.items, eventID); ... }
```

Only one of the two runs gets the bytes. Which one is a race between the decider's goroutine and the
observation loop, and the loser classifies **nothing** — for a print job or a clipboard copy, whose
whole content arrives out-of-band, "no content" produces an empty classification rather than an error.

**When the observation loop wins, the VERDICT path is the blind one.** `printDecider` finds no CPF and
returns `VerdictAllow`; the job with the payroll dump prints. The clipboard mediator's `OnCopy`
returns false, so sensitive content is not mediated and pastes anywhere. A prevention control that
fails open, nondeterministically, with nothing in the logs saying it happened — the second run's empty
classification is indistinguishable from a genuinely clean document.

Both existing tests pass because they hand `printDecider` a **buffered channel with no consumer**. The
production consumer is exactly what triggers the bug, and the test omits it.

Two more consequences worth naming, because they reach things shipped this week:

- **Two unified alerts for one job.** The dedup key is `decision:<decision_id>` and each run mints a
  fresh id, so they do not dedupe. XDR-4b's technique sequence requires two distinct *alerts* to
  evidence "A then B" — one moment cannot evidence "then" — and this makes one print job produce two
  alerts carrying the same techniques. The rule's central invariant is defeated by a duplicate.
- **Two ledger entries for one action**, in a hash-chained audit trail whose value is that it says
  what happened once.

## What changes

1. **The decider runs the pipeline; it does not also enqueue.** `eng.Process` already classifies,
   decides, records to the ledger, enforces and projects telemetry. The channel send adds a second
   run of all of it and a log line. It is removed from both producers.

2. **A regression test with the consumer attached**, counting classifier invocations and ledger
   entries for one job. Deterministic — which run wins the race is not, but *how many runs there are*
   is.

3. **`ContentStore` counts a resolve that found nothing** while entries exist, so a future duplicate
   consumer is visible rather than silent. The failure mode here was not the duplication, it was that
   the blind run looked exactly like a clean one.

## Impact

- **Behaviour:** one pipeline run per job instead of two. Fewer ledger entries, fewer alerts, half the
  classification work, and the verdict path always sees the content.
- **No schema, no proto, no config.**
- **Deliberately not in scope:** making `Resolve` non-destructive (it is one-shot on purpose — content
  must not linger in memory after classification, D29); a general "one event id, one pipeline run"
  guard in the engine, which would need an id cache with its own eviction policy and would paper over
  a producer bug rather than fix it.
