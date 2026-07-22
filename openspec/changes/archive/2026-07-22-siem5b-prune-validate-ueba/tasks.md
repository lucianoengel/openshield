## 1. Analyzer: prune + restore validation

- [x] 1.1 Add `PruneThreshold = 0.01` and `Analyzer.Prune(minCount float64) []string`: under the lock,
      delete each subject whose `decayedAt(now) < minCount` and return the removed ids.
- [x] 1.2 `WithSnapshot`: skip an entry whose `Count` is NaN, ±Inf, or `< 0` (in addition to the empty
      subject) — apply only well-formed entries.

## 2. Control plane: prune, validate, atomic persist

- [x] 2.1 `loadBaselines`: skip a row whose `count` is non-finite/negative or whose `last_seen` is after
      `s.now() + 1m` (clock-skew grace) — a corrupt/future row never enters the analyzer.
- [x] 2.2 `PersistBaselines`: prune the analyzer first (`Prune(PruneThreshold)`), then in ONE
      transaction DELETE the pruned subjects' rows and UPSERT the survivors; commit. No-op when disabled.

## 3. Verify + mutation guards

- [x] 3.1 Analyzer test (frozen clock): a subject decayed below the threshold is pruned + reported; a
      still-active subject survives; `WithSnapshot` drops a NaN/negative-count entry and keeps a valid one
      (assert via `ContextFor`/`Snapshot`).
- [x] 3.2 Real-PG test: observe a population, persist; a decayed subject's row is DELETEd by a later
      persist while active subjects remain; a hand-inserted row with a NaN/negative count or a future
      last_seen is NOT loaded (the fresh instance treats that subject as cold).
- [x] 3.3 Mutation guards (apply, FAIL, revert): (A) make `Prune` a no-op → the "row deleted" assertion
      FAILs; (B) drop the load validation → the corrupt-row-skipped assertion FAILs. Record it. (Confirmed 2026-07-22: (A) Prune no-op → sub_cold row not deleted → FAIL; (B) drop load validation → sub_nan/sub_neg loaded → FAIL; both reverted.)

## 4. Gate + record

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...` clean.
- [x] 4.2 decisions.md entry (next D-number); note `peerLastAlert` persistence is deferred.
- [x] 4.3 Roadmap + memory updated.
