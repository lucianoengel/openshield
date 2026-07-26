## 1. Invert the gate

- [x] 1.1 `natsx.JetStreamEnabled()` returns true unless `OPENSHIELD_JETSTREAM` is explicitly falsy
  (`0|false|off`, case-insensitive); an unrecognized value stays ENABLED (fail-loud, not a typo-disables-
  durability trap). Update the package doc to describe the default mode as durable at-least-once and the
  opted-out mode as core NATS at-most-once, without claiming loss-freedom.
- [x] 1.2 Unit-test the gate over every input: unset → on; `0`/`false`/`off`/`FALSE` → off; `1`/`true`/
  garbage → on.

## 2. Wire every producer through one helper

- [x] 2.1 `natsx.EnableDurableIfDefault(pub *SignedPublisher) error` — switches the publisher to JetStream
  when the default mode is in effect, returns a wrapped error NAMING the opt-out when JetStream is
  unavailable, and is a no-op when opted out.
- [x] 2.2 Call it in `cmd/openshield-engine`, `cmd/openshield-gateway` and `cmd/openshield-fleet-agent`,
  each right after the publisher is built and before the spool is attached, each FATAL on error.
- [x] 2.3 Test the helper at the seam against an embedded JetStream broker: with no override, a message
  published through the helper-configured publisher is received by a JetStream consumer (only true if the
  durable branch was taken). **Mutation:** remove the helper call → the stream consumer receives nothing →
  FAILs.
- [x] 2.4 Test that the helper is a no-op under the opt-out (core NATS still delivers, no stream needed).

## 3. Fail fast, never silently degrade

- [x] 3.1 Against a broker with JetStream DISABLED, the helper returns an error whose text names
  `OPENSHIELD_JETSTREAM`. **Mutation:** swallow the error and continue on core NATS → this FAILs.

## 4. The default path is genuinely durable

- [x] 4.1 End-to-end with real embedded JetStream + real Postgres and NO env override: publish signed
  telemetry while the control-plane consumer is down, start it, and assert every message lands (the case
  at-most-once loses). **Mutation:** revert the gate to opt-in → FAILs.
- [x] 4.2 Confirm the existing PLAT-2/R34-4 tests still pass unchanged — they set the env var explicitly, so
  they must keep working in both directions.

## 5. Deployment surface

- [x] 5.1 `compose.yaml`: the NATS service runs with JetStream enabled, so the dev stack matches the new
  default instead of refusing to start.

## 6. Gate and land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 6.2 Roadmap + decision register: PLAT-2 done; record the BREAKING upgrade note (JetStream-less broker
  must opt out), the engine/gateway wiring gap this fixed, and the honest limits (not loss-free, not
  exactly-once, bounded by stream limits).
- [x] 6.3 Commit with the `PLAT-2` handle, sync the delta spec, archive the change.
