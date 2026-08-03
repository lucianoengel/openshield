# Tasks — DLP-2 one job, one pipeline run

- [x] 1. Reproduce: a print job with a consumer attached is ALLOWED, with two ledger entries.
- [x] 2. Remove the enqueue from `printDecider` and the clipboard mediator's `OnCopy`; drop the
      `events` parameter from both so it cannot be restored.
- [x] 3. Update the existing print test to take the event from the pipeline rather than the channel.
- [x] 4. `ContentStore.Repeats` — a resolve for an already-consumed id, bounded window.
- [x] 5. Surface the counter per store in the engine's degraded-counter channel.
- [x] 6. Mutation-verify: the duplicate run, the store's one-shot premise, the repeat counter, the bound.
- [x] 7. Spec delta.
