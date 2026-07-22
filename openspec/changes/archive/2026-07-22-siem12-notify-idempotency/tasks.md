## 1. Deterministic idempotency id

- [x] 1.1 Replace `newNotifyID` (random) with `notifyID(n)` deriving the id from
      `kind|subject|agentID|window-bucket(At)` (SHA-256, `ntf_` + 12-byte hex); add `notifyDedupeWindow`.
- [x] 1.2 `emit` stamps `notifyID(n)` when `n.ID` is empty (a pre-set id is kept).

## 2. Server-side dedup

- [x] 2.1 Add a bounded, FIFO-evicting `dedupeSet` (`markNew` = atomic check-and-record, capacity cap).
- [x] 2.2 Add `Server.notifyDedupe` (init in `New`, cap 4096) + `NotifyDeduped` counter; `emit` suppresses
      a duplicate id and counts it. Nil-safe (a directly-constructed test Server keeps old behavior).
- [x] 2.3 Expose `openshield_notify_deduped_total` in metrics.go beside failures/dropped.

## 3. Verify + mutation guards

- [x] 3.1 Test: the same logical alert re-emitted 5s later (same window) delivers exactly once and
      `NotifyDeduped==1`; a later-window occurrence delivers again with a different id; a different
      subject delivers.
- [x] 3.2 Test: `notifyID` is deterministic (same input → same id; same-window re-detection → same id;
      different subject/window → different id).
- [x] 3.3 Mutation guards (apply, FAIL, revert): (A) disable the dedup check → the re-detection delivers
      twice → FAIL; (B) id from the raw timestamp instead of the window bucket → the 5s-apart re-detection
      gets a different id, delivers twice → FAIL.

## 4. Gate + record

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; cross-compile clean.
- [x] 4.2 decisions.md entry (next D-number).
- [x] 4.3 Roadmap + memory updated.
