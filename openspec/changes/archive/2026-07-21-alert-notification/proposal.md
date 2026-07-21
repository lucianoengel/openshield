## Why

No webhook/SMTP/pager code exists anywhere — a "high-severity alert" is a slog line
or a DB row, so a security team is never TOLD anything; it must go looking with
psql. This delivers the two aggregate detections that matter — a server-side
peer-UEBA alert (D54) and an agent going overdue (the dead-man's-switch, D50/D51) —
to a configured sink.

## What Changes

- `internal/notify` — a `Notification` (Kind [peer-alert | agent-overdue], pseudonymous
  Subject/AgentID per D23, RiskScore, At, Detail), a `Notifier` interface, a `Webhook`
  (POST JSON to a URL, short timeout), and a `Nop` default.
- `controlplane.Server` gains a notifier (default Nop) + `SetNotifier` and a
  best-effort `notify` helper (a delivery error is logged/counted, NEVER fatal — a
  down webhook must not break ingest or the detection; the alert is already recorded,
  delivery is additive, D30). `observePeer` notifies right after recording a peer alert.
- `Server.NotifyOverdue(ctx, threshold)` computes overdue agents, DEDUPs against an
  in-memory set (an agent alerts once when it goes silent, again only after it returns),
  notifies the fresh ones, returns the count. Pure `newlyOverdue` helper computes the delta.
- `cmd/openshield-server` builds a Webhook from `OPENSHIELD_ALERT_WEBHOOK`, SetNotifier,
  and schedules `NotifyOverdue` via `retain.Loop`.

## Capabilities

### Modified Capabilities
- `control-plane`: alerts are delivered via a notifier (webhook), best-effort.
- `heartbeat`: overdue agents trigger a deduplicated notification.

## Impact

- New `internal/notify`; notifier field + NotifyOverdue in the server; scheduling in
  the server binary; `docs/decisions.md` D83.
- Proven: the Webhook POSTs the JSON to an httptest server; `newlyOverdue` dedups; and
  `NotifyOverdue` against real Postgres + a fake notifier notifies once and dedups.
- NOT in scope (stated): SMTP/Slack/PagerDuty adapters (a deployer bridges the webhook);
  routing/severity/escalation; retry/queue (best-effort — the alert is still recorded);
  notifying on individual endpoint decisions (too high-volume). Respects D23, D50/D51,
  D54, D30.
