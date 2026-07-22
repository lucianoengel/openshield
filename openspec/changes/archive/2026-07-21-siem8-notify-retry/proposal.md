# SIEM-8: retry a transient notification failure

## Why

Alert delivery (D83) is single-shot: `Webhook.Notify` POSTs once, and any failure — a 5xx from
the receiver, a timeout, a connection refused while the receiver is redeploying — drops the
notification. The detection is still recorded (D30), but the human is never paged, which defeats
the point of notification. A momentary blip should not lose an alert.

## What Changes

- **A `Retrying` notifier decorator** wraps any `Notifier` and re-attempts a TRANSIENT failure
  with bounded exponential backoff (default 3 attempts, 200ms base, capped), respecting context
  cancellation. Delivery stays best-effort — after the last attempt the final error is returned
  for the caller to log; retry widens the window a blip is survived, it does not make delivery
  guaranteed.
- **A permanent/transient distinction** (`notify.Permanent`): a 4xx client error (bad URL, auth,
  payload — except 429) and a notification that will not serialize are marked permanent and NOT
  retried, since retrying cannot fix them. A 5xx, a 429, and transport errors are transient and
  retried.
- **The server wraps its webhook in retry** — `OPENSHIELD_ALERT_WEBHOOK` delivery now goes
  through `Retrying`, with the attempt count configurable via `OPENSHIELD_ALERT_RETRIES`.

This modifies the `control-plane` capability's alert-delivery requirement. No core change.

## Impact

- Affected specs: `control-plane`
- Affected code: `internal/notify/retry.go` (new), `internal/notify/notify.go` (4xx→permanent
  classification), `cmd/openshield-server/main.go` (wrap in retry, `envInt` helper).
- Not in scope (stated): durable/queued delivery that survives a receiver down for the whole
  backoff window (a heavier, separate mechanism); jitter on the backoff; per-notification
  dead-lettering; retry of the overdue-timer path beyond the shared notifier.
