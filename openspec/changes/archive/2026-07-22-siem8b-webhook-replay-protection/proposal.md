## Why

A signed webhook can be replayed forever. The HMAC covers only the request body, with no timestamp or
nonce, so a captured `(body, X-Openshield-Signature)` pair validates indefinitely — an attacker who
records one delivery can re-POST it to the receiver any time to re-fire a stale alert. Signing must
bind the message to a time so a receiver can reject a stale replay.

## What Changes

- The webhook signs `"<unix-ts>." + body` (not just `body`) and sends the timestamp in an
  `X-Openshield-Timestamp` header alongside the existing `X-Openshield-Signature`.
- Verification recomputes the HMAC over `"<ts>." + body` (constant-time) AND rejects a timestamp
  outside a freshness window (stale or implausibly future) — so a captured delivery stops validating
  once it ages past the window.
- Per-sink secrets are already supported (each `Webhook` carries its own `Secret`); no change needed
  there — noted so replay protection and per-sink isolation are both covered.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `control-plane`: the authenticated webhook binds its signature to a timestamp and a receiver rejects
  a stale-timestamp replay, so a captured signed delivery cannot be replayed indefinitely.

## Impact

- **Code:** `internal/notify/sign.go` (`Sign` takes a timestamp; `VerifySignature` takes the timestamp
  header + a freshness window; add `TimestampHeader`), `internal/notify/notify.go` (`Webhook` gets an
  injectable clock and sends both headers), and the tests.
- **No proto/core change.** Delivery semantics (best-effort, off-ingest, retry/permanence) unchanged.
- **BREAKING for a receiver that verified the old body-only signature** — it must now verify over
  `"<ts>." + body` and read the timestamp header. Documented as a migration note.
