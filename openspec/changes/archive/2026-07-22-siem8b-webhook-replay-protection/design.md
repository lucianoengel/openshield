## Context

`Sign(secret, body)` returns `"sha256=" + hex(HMAC-SHA256(body))`; `Webhook.Notify` sets it as
`X-Openshield-Signature`. Nothing binds the signature to a time, so `(body, sig)` is valid forever —
a recorded delivery replays indefinitely. This is the standard webhook-replay problem; the standard
fix (Stripe-style) is to sign a timestamp-prefixed payload and have the receiver reject a stale
timestamp.

## Goals / Non-Goals

**Goals:**
- Bind the signature to a timestamp; a receiver rejects a replay outside a freshness window.
- Keep the constant-time MAC comparison and the "no secret → no header, body unchanged" behavior.
- Testable with a frozen clock (no wall-clock flakiness).

**Non-Goals:**
- A server-side nonce/seen-set on the RECEIVER (the receiver is a third party; the timestamp window is
  the interoperable mechanism). A bounded window is sufficient against replay.
- Per-sink secrets — already supported (each `Webhook` has its own `Secret`); nothing to change.

## Decisions

### D-a · Sign `"<unix-ts>." + body`; carry the timestamp in a header
`Sign(secret, ts, body)` signs `strconv(ts) + "." + body`. The sender sets `X-Openshield-Timestamp:
<ts>` and `X-Openshield-Signature: sha256=<hex>`. Prefixing (not appending) the timestamp matches the
Stripe convention and keeps the body bytes intact after the separator.

### D-b · Verification checks freshness AND the MAC
`VerifySignature(secret, body, tsHeader, sigHeader, now, tolerance)` parses `tsHeader`; if it does not
parse, or `abs(now.Unix() - ts) > tolerance`, it returns false BEFORE the MAC check (a stale or
implausibly-future timestamp is rejected outright); otherwise it recomputes `Sign(secret, ts, body)`
and compares constant-time. A default `ReplayTolerance = 5 * time.Minute` is exported for receivers.

*Alternative considered:* only check the MAC and let the caller check the timestamp separately.
**Rejected** — bundling makes replay rejection the default, not an easy-to-forget extra step.

### D-c · The webhook stamps the time from an injectable clock
`Webhook` gets `now func() time.Time` (default `time.Now`, set in `NewWebhook`), so `Notify` stamps a
real time in production and a frozen time under test. Only when a secret is configured are the two
headers added; with no secret the request is byte-for-byte unchanged (preserved).

## Risks / Trade-offs

- **Clock skew between sender and receiver** → the 5-minute window tolerates normal skew; a receiver
  can widen it. Documented.
- **Breaking a receiver that verified the old body-only signature** → the signed payload changed;
  documented as a migration note. This is a security fix, not a silent format drift.
- **A replay WITHIN the window still validates** → inherent to a timestamp-window scheme; the window
  bounds the exposure, and a receiver wanting exactly-once can additionally dedupe on the
  notification id (SIEM-12). Noted.

## Migration Plan

Receivers must verify over `"<ts>." + body` using the `X-Openshield-Timestamp` header and reject a
stale timestamp. Drop-in on the sender side (headers added). Rollback reverts to the replayable
body-only signature.

## Open Questions

None.
