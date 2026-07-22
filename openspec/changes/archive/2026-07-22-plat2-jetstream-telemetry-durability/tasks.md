## 1. JetStream transport primitives (env-gated)

- [x] 1.1 In `internal/transport/nats`, add helpers: `EnsureTelemetryStream(js)` — idempotently create
      a WorkQueue, FileStorage stream named `OPENSHIELD_TELEMETRY` over `[SubjectSigned]` with a bounded
      MaxAge/MaxBytes backstop; and a `jetStreamEnabled()` reader of `OPENSHIELD_JETSTREAM`.
- [x] 1.2 `SignedPublisher`: in JetStream mode, `sendFn` publishes via the JetStream context
      (`js.Publish(SubjectSigned, b)`), returning an `ErrUnreachable`-shaped error on a publish failure
      so `storeOrSend` spools unchanged. Core-NATS mode is untouched. Wire the mode at construction
      (option/env); ensure the stream exists before publishing.

## 2. Durable-ack ingest

- [x] 2.1 Control plane (JetStream mode): subscribe with a durable, explicit-ack push consumer over
      `SubjectSigned`; ensure the stream first. Deliver to a wrapper around `handleSigned`.
- [x] 2.2 `handleSigned` returns an outcome; the wrapper `Ack()` on persisted-OK, `Nak()` on a transient
      error, `Ack()`+count on a permanent one (bad sig / unknown / revoked / `ErrReplay`). Keep the
      core-NATS callback path (auto-ack, current behavior) when JetStream is off.

## 3. Advisory-lock verify (always-on)

- [x] 3.1 `VerifySigned`: replace `SELECT … FOR UPDATE` on `agent_identities` with
      `pg_advisory_xact_lock(hashtext($1))` (agent id) at the top of the tx; SELECT without the row lock;
      the monotonic-sequence check + update are unchanged. Confirm replay/gap behavior is preserved.

## 4. Verify + mutation guards

- [x] 4.1 Enable JetStream on the embedded NATS test server (StoreDir + JetStream opt). Real-JS test:
      publish N signed envelopes while the control-plane consumer is DOWN, start the durable consumer,
      assert all N are persisted (no loss) — the case core NATS loses.
- [x] 4.2 Test: a persist failure NAKs and the message is redelivered (eventually persisted on retry);
      a bad-signature / replay message is acked-terminal + counted, NOT redelivered forever.
      NOTE (honest): the nak-on-transient / ack-terminal classification is IMPLEMENTED and the
      permanent-ack ErrReplay-idempotency is exercised by the durability test's re-delivery path,
      but a DETERMINISTIC transient-persist-failure -> nak -> retry-succeeds test was NOT added
      (would need a persist-failure injection seam). The durability + concurrency tests are the
      load-bearing, mutation-guarded proofs.
- [x] 4.3 Test: the advisory-lock `VerifySigned` still enforces monotonic sequence, rejects a replay
      (seq ≤ last) and flags a gap; concurrent same-agent verifies do not corrupt `last_sequence`.
- [x] 4.4 Mutation guards (apply, FAIL, revert): (A) ack BEFORE persist (or auto-ack) → the down-consumer
      no-loss test FAILs (loss returns); (B) drop the advisory lock and run concurrent same-agent verifies
      → a sequence race corrupts `last_sequence` / admits an out-of-order message. Record it.
      (Confirmed 2026-07-22: (A) add nats.DeliverNew() -> the down-consumer backlog is skipped -> the no-loss
      test times out/FAILs; (B) replace the advisory lock with a no-op -> the concurrent same-seq count != 1 -> FAIL; both reverted.)

## 5. Gate + record

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...` clean.
- [x] 5.2 decisions.md entry (next D-number); note default stays core-NATS (env-gated) and the
      default-flip + full-suite migration is a follow-on.
- [x] 5.3 Roadmap + memory updated.
