## 1. Multiple sinks (fanout)

- [x] 1.1 Add `Multi` notifier (`internal/notify/sink.go`): `Notify` attempts every sink, joins errors with `errors.Join`, aggregate is `Permanent` only if all failing sinks were permanent; empty `Multi` is a no-op success.
- [x] 1.2 Test: a two-sink fanout with a failing first sink still delivers to the second and returns an aggregate error; an all-permanent aggregate is permanent while a mixed aggregate is not.
- [x] 1.3 Mutation-test the fanout guard: early-return on first error → the healthy sink is not delivered to (test fails).

## 2. HMAC-signed webhook body

- [x] 2.1 Add `Sign(secret, body) string` (`sha256=<hex>`) and constant-time `VerifySignature(secret, body, header) bool` to `internal/notify`.
- [x] 2.2 Add `Secret []byte` to `Webhook`; when non-empty, set `X-Openshield-Signature` from `Sign` over the exact marshaled body; when empty, send no header (byte-for-byte unchanged).
- [x] 2.3 Test: signed body verifies with the right secret; a tampered body and a wrong secret both fail; a wrong/absent/malformed header is rejected; an unsigned webhook sends no header.
- [x] 2.4 Mutation-test: replace `hmac.Equal` with `bytes.Equal`/`==` still passes functionally, so assert constant-time via the API contract; mutate the signed input (sign over a fixed string instead of the body) → the tamper test fails.

## 3. Wire the binary

- [x] 3.1 `cmd/openshield-server`: parse `OPENSHIELD_ALERT_WEBHOOK` as comma-separated URLs → one `Retrying(Webhook)` each, combined via `Multi` when >1; apply `OPENSHIELD_ALERT_WEBHOOK_SECRET` to every webhook when set.
- [x] 3.2 A single URL with no secret produces the exact prior behavior.

## 4. Gate

- [x] 4.1 `openspec validate siem8-notify-robustness --strict` passes.
- [x] 4.2 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; then archive + sync spec + commit/push.
