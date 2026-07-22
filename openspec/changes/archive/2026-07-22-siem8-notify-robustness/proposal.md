## Why

Alert delivery (D83) is a single best-effort webhook. Retry/backoff already landed
(SIEM-8, `notify.Retrying`), but two robustness gaps remain: a deployer can configure
only ONE sink (no paging PagerDuty *and* archiving to a SIEM), and the webhook body is
unauthenticated — a receiver at a webhook URL cannot tell a genuine control-plane alert
from a forged or tampered POST. Both undermine "the human is reliably and truthfully
told," which is the whole point of notification.

## What Changes

- Add a `Multi` fanout `Notifier` that delivers one `Notification` to N inner sinks
  best-effort: every sink is attempted even if one fails, the aggregate error is
  returned for the caller to log, and the aggregate is `Permanent` only if ALL inner
  failures are permanent. Composition contract: `Multi` is the OUTER wrapper and each
  inner sink is individually wrapped in `Retrying`, so a retry re-attempts only the
  failed sink and never re-pages a sink that already succeeded.
- Add optional HMAC-SHA256 signing to `Webhook`: an optional `Secret`; when set, the
  exact JSON body is signed and sent as `X-Openshield-Signature: sha256=<hex>` (the
  GitHub-webhook convention). Add exported `Sign(secret, body)` and constant-time
  `VerifySignature(secret, body, header)` so a Go receiver — and the tests — can verify.
  Unset secret = unsigned, byte-for-byte unchanged from today.
- Wire `cmd/openshield-server`: `OPENSHIELD_ALERT_WEBHOOK` accepts multiple
  comma-separated URLs (each individually retried, then fanned out via `Multi`);
  `OPENSHIELD_ALERT_WEBHOOK_SECRET` (optional) sets the signing secret.

No core, proto, or ledger change; delivery is additive and stays best-effort (D30).

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `control-plane`: alert delivery gains fanout to multiple sinks and optional
  HMAC-authenticated webhook bodies (the SIEM-8 robustness requirements).

## Impact

- `internal/notify/` — new `Multi` notifier; `Webhook` gains `Secret` + signing;
  new `Sign`/`VerifySignature` helpers. No dependency changes (stdlib `crypto/hmac`,
  `crypto/sha256`, `crypto/subtle`).
- `cmd/openshield-server/main.go` — parse multiple webhook URLs + optional secret.
- Backward compatible: a single unsigned webhook URL behaves exactly as before.
