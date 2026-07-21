## Context

`SignedPublisher.publish` does `seq := p.seq.Add(1)` on an in-memory counter and
signs `(seq, payload)`. `controlplane.VerifySigned` loads `last_sequence FOR
UPDATE`, and: `seq <= last → ErrReplay`; `seq == last+1 → accept`; `seq > last+1 →
accept + Gap`. So forward jumps are safe (gaps), backward/equal is rejected. The
only failure is a RESET to 0 on restart, which makes every early post-restart seq
a replay.

## Goals / Non-Goals

**Goals:**
- The sequence is strictly monotonic across restarts (never reused), with bounded
  write cost (not one fsync per message).
- A restarted agent's telemetry is accepted, not rejected as a replay.
- The transport doc matches the code.

**Non-Goals:**
- Durability of the messages themselves across a control-plane outage — that is
  the offline queue (D40), wired separately (#4b).
- Exactly-once or gap-free delivery — gaps are accepted and counted by design
  (D50); a persisted reservation trades a possible gap for crash-safety.
- JetStream — out of scope; the doc is corrected to stop claiming it.

## Decisions

**Reservation-based persistence, block size N.** The store keeps a persisted
HIGH-WATER `hw`. On publish, `s := seq.Add(1)`; if `s > hw`, reserve a new block:
`hw = s + N` and persist `hw` (atomic temp+rename). So the file is written once
per N publishes. On startup, `Load()` returns the last persisted `hw`, and the
counter starts there — so the next publish is `hw+1`, strictly greater than any
sequence that could have been used before the crash (used sequences were all
`<= hw`). Reserved-but-unused sequences (between the last used and `hw`) simply
never appear — a gap the control plane accepts.

**Atomic persistence, mirroring D46.** The high-water file is written temp+rename
at 0600, the same discipline as `SaveSignerFile`. A corrupt/short file fails to
load loudly (the publisher refuses to start rather than silently reset to 0 and
reintroduce the bug).

**Backward-compatible constructor.** `NewSignedPublisher(agentID, id, conn)` stays
in-memory (for tests and callers that do not persist). A new
`NewSignedPublisherWithSeq(agentID, id, conn, store)` (or a `SeqStore` option)
takes the persistence. The fleet agent uses a file-backed store at
`OPENSHIELD_SEQ_FILE`.

**Doc correction is part of the same honesty fix.** The `nats.go` package comment
is reworded from "over NATS JetStream" to "core NATS (at-most-once)", naming the
offline queue as the durability path — so the code and its own description agree.

## Risks / Trade-offs

- **A reserved block is lost on crash → a gap.** After a crash, up to N-1
  reserved-but-unused sequences are skipped, producing a gap the control plane
  records. That is the intended trade: a bounded gap instead of a per-message
  fsync or a false-replay storm. N is chosen modestly (e.g. 100).
- **The seq file is now state to protect.** If it is deleted, the publisher
  resets — same failure as today. It lives beside the signer state (D46) under
  the agent's data dir; its loss is an operational error, documented. A wrong/
  corrupt file fails loudly, it does not silently reset.
- **Not gap-free.** This fixes false REPLAYS, not gaps; gaps remain a normal,
  accepted, counted signal (D50). The control plane's gap counter will tick after
  a crash — correctly, because a crash IS a small suppression.
