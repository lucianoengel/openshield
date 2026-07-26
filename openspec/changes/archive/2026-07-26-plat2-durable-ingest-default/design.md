## Context

At `HEAD`:

- `natsx.JetStreamEnabled()` = `os.Getenv("OPENSHIELD_JETSTREAM") != ""` — opt-in, and its own comment says
  "flipping the default is a follow-on".
- `controlplane.Run` branches on that helper and, when on, subscribes with `nats.Durable(...)`,
  `ManualAck()`, `AckExplicit()`, and Naks transient failures with backoff (R34-4).
- `SignedPublisher.UseJetStream()` derives a JetStream context and ensures the stream.
- **`UseJetStream()` is called from exactly one place: `cmd/openshield-fleet-agent`.** The engine and the
  gateway do not call it. Their `sendFn()` therefore takes the core-NATS branch.

So the durable path is real end-to-end only for simulated traffic. Everything needed to fix it exists; it
just is not connected at two of three producers.

## Goals / Non-Goals

**Goals:** durable by default; all three producers on the same path; an unavailable JetStream fails loudly;
the spool and the ledger keep their existing roles.

**Non-Goals:** exactly-once, loss-freedom, the other NATS subjects, broker topology/HA (PLAT-6/PLAT-9).

## Decisions

### D-1: Invert the single helper rather than adding a second flag

`JetStreamEnabled()` returns true unless `OPENSHIELD_JETSTREAM` is explicitly falsy (`0`, `false`, `off`,
case-insensitive). Producers and the consumer keep reading the *same* function.

The alternative — a new `OPENSHIELD_JETSTREAM_DISABLE` alongside the old flag — was rejected: two flags
governing one wire mode is how a publisher and a consumer end up in different modes, and that failure is
silent (the publisher writes to a stream nobody consumes, or publishes core-NATS messages the durable
consumer never sees). One helper makes disagreement unrepresentable.

An unrecognized value (`OPENSHIELD_JETSTREAM=maybe`) is treated as **enabled**, matching the fail-loud
default rather than quietly disabling durability on a typo.

### D-2: Fail fast on unavailable JetStream

If `UseJetStream()` errors, the producer exits with an error naming `OPENSHIELD_JETSTREAM=0`.

*Alternative: fall back to core NATS with a warning.* Rejected, and this is the ticket's central judgement.
A warning at startup is read once, if at all; the deployment then runs for months believing telemetry is
durable while it is at-most-once. That is precisely the "claims a guarantee the code does not provide"
failure the transport spec forbids. A security product may refuse to start; it may not quietly weaken its
evidence path.

The cost is honest and stated: an upgrade onto a JetStream-less broker breaks until the operator enables
JetStream or opts out. It is a one-line fix, the error says so, and it belongs in PLAT-9's upgrade runbook.

### D-3: Assert the producer path at the seam, not by reading `main()`

The bug this ticket fixes is "a producer forgot to call `UseJetStream()`". A test that inspects startup code
would not catch it, and a test that runs the binaries would be an integration harness this repo does not
have. So the test constructs a publisher the way a producer does, publishes with no override, and asserts a
**JetStream consumer receives the message** — which is only true if the publisher took the durable branch.

To keep that honest, the wiring is extracted into one helper (`natsx.EnableDurableIfDefault(pub)`) that all
three binaries call, and the test exercises that helper. A future producer that skips the helper is still a
gap — so the helper is the thing to look for in review, and the test pins its behavior.

### D-4: The spool and the ledger do not move

`storeOrSend` already routes an unaccepted publish to the spool in both modes, and the JetStream `sendFn`
returns the publish error so the spool catches it. Nothing about D40/D67 or D12/D30 changes. The stream's
`MaxAge`/limits stay as the backstop that prevents a down consumer from filling the disk — which is exactly
why the proposal refuses to call this loss-free.

## Risks / Trade-offs

- **Breaking upgrade on a JetStream-less broker** → deliberate (D-2), loud, one-line opt-out, runbook item.
- **The dev compose stack must enable JetStream** → the NATS service needs `-js`; if it is missed, every
  producer refuses to start, which is noisy but self-diagnosing.
- **At-least-once means duplicates** → the ingest is idempotent by verified sequence (a replay is detected
  and terminal-ACKed), so a duplicate is counted, not double-stored. Unchanged by this ticket, but it is
  what makes redelivery safe.
- **A long consumer outage still drops** once the stream's bounds are hit. Stated in the proposal rather
  than papered over; raising the bounds is an operator decision with a disk cost.

## Migration Plan

Enable JetStream on the broker (`nats-server -js`, already the case for the dev container) before deploying;
or set `OPENSHIELD_JETSTREAM=0` to keep core NATS. Rollback is the previous binaries or the opt-out. No
schema or proto change.

## Open Questions

- Should the other subjects (risk, posture, attestation) eventually become durable too? They are
  coordination, not evidence, and a missed risk update is corrected by the next one — so probably not, but it
  is worth revisiting if a lost posture update ever causes a wrong decision.
