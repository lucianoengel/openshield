# Tasks — alert notification (D83)

## 1. Notify package

- [x] 1.1 `internal/notify`: `Notification{Kind, Subject, AgentID, RiskScore, At, Detail}`; `Notifier` interface (`Notify(ctx, Notification) error`); `Webhook{URL, client}` (POST JSON, short timeout); `Nop`.

## 2. Server notifier + peer-alert

- [x] 2.1 `Server` gains `notifier notify.Notifier` (default Nop), `SetNotifier`, `NotifyFailures` counter, and a best-effort `notify(ctx, n)` helper (log/count on error, never propagate).
- [x] 2.2 `observePeer`: call `s.notify` with a peer-alert Notification right after `recordPeerAlert`.

## 3. Overdue notification

- [x] 3.1 `newlyOverdue(prev map[string]bool, current []string) (fresh []string, next map[string]bool)` — pure delta+dedup.
- [x] 3.2 `Server.NotifyOverdue(ctx, threshold) (int, error)` — Overdue → newlyOverdue against `s.notifiedOverdue` → notify fresh → update the set → return count.

## 4. Binary

- [x] 4.1 `cmd/openshield-server`: build a `notify.Webhook` from `OPENSHIELD_ALERT_WEBHOOK` when set, `SetNotifier`, schedule `NotifyOverdue(OPENSHIELD_OVERDUE_THRESHOLD [15m])` via `retain.Loop` on `OPENSHIELD_OVERDUE_INTERVAL [5m]`.

## 5. Proof (guards, each mutation-tested)

- [x] 5.1 **Test**: `notify.Webhook` POSTs the Notification JSON to an httptest server; the server receives the right Kind + fields.
- [x] 5.2 **Test**: `newlyOverdue` returns only agents newly overdue vs the previous set and carries the set forward.
- [x] 5.3 **Test** (real Postgres + fake Notifier): seed a stale agent; `NotifyOverdue` notifies exactly 1; a second call notifies 0 (dedup); after a fresh heartbeat the agent can alert again.

## 6. Docs, ship

- [x] 6.1 `docs/decisions.md` D83: alerts are delivered (webhook) on peer-UEBA alerts and overdue agents; best-effort; overdue deduplicated; closes the "no alert delivery" gap.
- [x] 6.2 `openspec validate alert-notification --strict`; `make all` + `-race`; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| newlyOverdue treats all current as fresh (no dedup) | `TestNewlyOverdueDedups`, `TestNotifyOverdueDeliversAndDedups` |
| the next set never tracks current overdue | `TestNotifyOverdueDeliversAndDedups` |

THE VERDICT (D83): alerts are delivered (webhook) on peer-UEBA alerts and overdue agents; best-effort
so a down sink never breaks ingest; overdue notifications deduplicated (once per silence). The system
can finally tell a human. NOT in scope: SMTP/Slack/PagerDuty adapters; routing/escalation; retry/queue;
per-decision notifications.
