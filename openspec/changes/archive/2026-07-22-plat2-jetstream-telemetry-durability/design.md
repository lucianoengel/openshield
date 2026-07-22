## Context

All signed telemetry flows over ONE subject, `SubjectSigned`: the publisher's `sendFn` does
`conn.Publish(SubjectSigned, b)` (or spools when unreachable), and the control plane does
`subscribeCounted(conn, SubjectSigned, handleSigned)`. `handleSigned` calls `VerifySigned` (a per-agent
`FOR UPDATE` tx that checks the monotonic sequence and persists). Core NATS is at-most-once: a slow or
restarting consumer drops messages (SEC-4 counts them; D116). JetStream with explicit ack makes the
stream hold a message until the control plane has actually persisted it — the drop window closes.

## Goals / Non-Goals

**Goals:**
- Durable, at-least-once, explicit-ack ingest of signed telemetry that survives a consumer restart.
- Ack only after persist; nak transient failures; ack-terminal permanent ones — no redelivery storm.
- Replace the ingest-serializing `FOR UPDATE` with a per-agent advisory lock.
- Land it provably without rewriting every telemetry test — env-gated.

**Non-Goals:**
- Making JetStream the DEFAULT and migrating the whole telemetry test suite (noted follow-on).
- Moving risk/posture (best-effort, gateway-bound) to JetStream.
- Using stream retention as evidence (D12 — the ledger is the record).
- HA (PLAT-2b) — this is its prerequisite, not its delivery.

## Decisions

### D-a · One WorkQueue, file-backed stream over `SubjectSigned`
The control plane, on connect (JetStream mode), idempotently ensures a stream (name e.g.
`OPENSHIELD_TELEMETRY`) with `Subjects=[SubjectSigned]`, `Storage=File` (survives restart),
`Retention=WorkQueue` (a message is removed once the single consumer acks — a delivery bus, not
evidence, honoring D12), and a bounded `MaxAge`/`MaxBytes` backstop. WorkQueue fits because the control
plane is the sole telemetry consumer.

*Alternative considered:* `Limits` retention (messages linger until age/size). **Rejected** — WorkQueue
deletes on ack, which is the precise "bus, not store" shape and bounds storage to the unacked backlog.

### D-b · Publisher uses `js.Publish`; the spool is unchanged
`sendFn` (JetStream mode) publishes via the JetStream context and checks the returned `PubAck`; a
publish error is `ErrUnreachable`-shaped so `storeOrSend` spools it exactly as today. The spool stays
the PRE-broker buffer (broker unreachable); the stream is the durability AFTER the broker accepts it.
Together: no loss from agent to persisted, across either an agent-side outage or a consumer-side one.

### D-c · Explicit-ack consumer; ack AFTER persist, nak transient, ack-terminal permanent
A durable push subscription (`nats.Durable`, `nats.ManualAck`, `nats.AckExplicit`) delivers to a
wrapper around `handleSigned`. The wrapper classifies the outcome:
- **persisted OK** → `msg.Ack()`.
- **transient** (a DB/infra error from `VerifySigned`/persist) → `msg.Nak()` → redelivery after a
  backoff; the message is NOT lost.
- **permanent** — bad signature, unknown agent, revoked, or `ErrReplay` (a redelivered message whose
  sequence was already applied — idempotent) → `msg.Ack()` (terminal; redelivering a permanently
  bad/duplicate message forever is itself a failure mode) and count it (the existing verified/dropped
  counters).

This is the crux: acking BEFORE persist re-opens the exact drop window; the `ErrReplay`-must-ack rule
is what makes redelivery safe against the monotonic-sequence guard.

### D-d · Per-agent advisory lock replaces `FOR UPDATE`
`VerifySigned` takes `pg_advisory_xact_lock(hashtext($agentID))` at the top of the tx instead of
`SELECT … FOR UPDATE` on `agent_identities`. Same guarantee — the sequence check-and-update is
serialized per agent — without holding the identity ROW lock across the whole transaction (which also
blocked concurrent reads of that row). The lock releases at commit/rollback (xact-scoped). Behavior is
identical: monotonic sequence enforced, replay/gap detected.

### D-e · Env-gated, backward compatible
`OPENSHIELD_JETSTREAM` selects the mode. Off (default): the current core-NATS publish/subscribe, so
every existing test is unchanged. On: the durable path. The publisher and the subscriber each read the
env at construction. This lets the safety-critical migration land with focused JetStream tests while
the default and the broad test suite are untouched; the follow-on flips the default.

## Risks / Trade-offs

- **Ack-timing correctness is safety-critical** → ack strictly after a successful persist; the
  down-consumer test proves no loss and the mutation (ack-before-persist) proves the test catches a
  regression.
- **Redelivery + monotonic sequence** → a redelivered already-applied message verifies as `ErrReplay`
  and is acked-terminal, so it neither loops nor is mis-persisted. Explicitly tested.
- **WorkQueue single-consumer constraint** → the control plane is the sole telemetry consumer; if HA
  (PLAT-2b) adds a second, it uses a shared durable consumer (queue group), not a second overlapping
  one — noted for PLAT-2b.
- **Env-gated default stays at-most-once** → honest: the durability capability exists and is proven;
  the deployment enables it, and flipping the default is the named follow-on.
- **advisory-lock hash collisions** → `hashtext` collisions would serialize two unrelated agents
  occasionally (a rare, harmless extra wait), never a correctness issue (the sequence is still checked
  against the right row).

## Migration Plan

Additive and env-gated: deploy, then set `OPENSHIELD_JETSTREAM=1` on the server and agents to enable
durable ingest (the stream is auto-created). Rollback = unset the env (core NATS). The advisory-lock
change is transparent (same behavior). No schema/proto change.

## Open Questions

- Push vs pull consumer: push (callback) matches the current subscribe shape and is chosen; a pull
  consumer (explicit fetch/batch) is a possible later refinement for backpressure, not needed now.
