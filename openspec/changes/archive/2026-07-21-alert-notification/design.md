## Context

The server records peer alerts (`peer_alerts`, D54) and can compute overdue agents
(`Server.Overdue`, D50/D51), and now an operator can READ both (D82) — but nothing is
PUSHED; a human must poll. Alert delivery is the missing half of "detection".

## Goals / Non-Goals

**Goals:** deliver the two aggregate detections to a configured sink; best-effort;
overdue notifications deduplicated.

**Non-Goals:** SMTP/Slack/PagerDuty adapters; routing/severity/escalation; retry/queue;
per-decision notifications.

## Decisions

**A generic webhook, not a bespoke integration.** `notify.Webhook` POSTs the
`Notification` as JSON to a URL — a deployer bridges it to Slack/PagerDuty/email with an
off-the-shelf receiver. One adapter, JSON, no vendor coupling. `Nop` is the default so
notification is opt-in (configure a URL to turn it on).

**Best-effort, additive, never fatal.** The alert is already recorded (peer_alerts, or
computable from telemetry) — the notification is a COPY pushed to a human (D30). A down
or slow webhook must not break telemetry ingest or the detection, so `s.notify` logs
and counts a delivery error and returns; the ingest path and `observePeer` do not
propagate it. Losing a notification degrades responsiveness, not the record.

**Overdue notifications are DEDUPLICATED.** An agent that has been silent for hours is
overdue every time the check runs; notifying each interval would be a pager storm. The
server keeps an in-memory `notifiedOverdue` set: an agent is notified the FIRST time it
appears overdue and removed when it reports again (so it can alert on a future silence).
`newlyOverdue(prev, current)` is a pure function of the previous set and the current
overdue list, so the dedup logic is unit-testable without a database.

**Peer-alert notifications ride the existing cooldown.** `observePeer` already throttles
repeat peer alerts per subject (the peer cooldown); the notification fires only when a
peer alert is actually recorded, so it inherits that throttle — no separate dedup needed.

## Risks / Trade-offs

- **In-memory dedup resets on restart.** After a server restart every currently-overdue
  agent notifies once more (the set is empty). Acceptable — a restart re-alerting on
  genuinely-silent agents is a feature, not a storm; persisting the set is a noted
  follow-up.
- **No retry.** A webhook that is down when an alert fires misses it (the alert is still
  recorded and readable via D82). A durable delivery queue is out of scope, stated.
- **Best-effort hides a broken sink.** A misconfigured webhook fails silently except for
  a log line + counter. The counter is the signal; a health surface for it is a noted
  follow-up.
