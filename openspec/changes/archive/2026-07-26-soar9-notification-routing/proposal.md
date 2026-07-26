## Why

Every notification the control plane produces goes to every configured sink. A `low`-severity peer alert
wakes whoever is on the pager, and a `critical` incident lands in the same chat channel as everything
else — so the pager stops meaning anything and people mute it, which is how an alerting system stops
working while still appearing to run.

Three shipped tickets each recorded the same residual and deferred it here: SOAR-2 ("no escalation timers
or on-call routing — SOAR-9 owns routing"), SOAR-3 ("it notifies nobody that an approval is pending —
SOAR-9 owns routing") and SOAR-4, whose `wait-for-approval` step **parks a run waiting for a human who
was never told**. That last one is not a cosmetic gap: an automated playbook can currently stall
indefinitely on an approval nobody knows exists.

## What Changes

- **A routing table** over the existing multi-sink fanout: ordered rules matching on notification **kind**
  and **minimum severity**, selecting **named** sinks. **First match wins**, like a firewall rule set —
  so "CRITICAL to the pager only" is expressible, which a union-of-all-matches semantic cannot do.
- **Sinks gain names.** `OPENSHIELD_ALERT_WEBHOOK` accepts `name=url` entries; a bare URL keeps working
  and is auto-named, so existing deployments are unaffected.
- **An unmatched notification goes to EVERY sink and is counted** (`openshield_notify_unrouted_total`).
  Dropping a critical alert because a routing table was misconfigured is the worst available outcome;
  over-notifying is recoverable and visible. Fail-open, loudly — the same rule the watchdog and the exec
  gate follow.
- **Notifications carry a severity.** `emit` stamps it from the existing risk→bucket mapping when a
  producer leaves it unset, so routing has something to match on and the mapping keeps exactly one home.
- **A pending approval now notifies** (`KindApprovalPending`), closing SOAR-3's residual and making
  SOAR-4's `wait-for-approval` step usable: the human who must approve is told there is something to
  approve.

## Capabilities

### New Capabilities
- `notification-routing`: an ordered kind/severity → named-sink routing table over the existing fanout,
  with a counted fail-open for unmatched notifications.

### Modified Capabilities
- `four-eyes-approvals`: opening an approval request emits a notification, so a request is not waiting on
  someone who was never told it exists.

## Impact

- **New code**: `internal/notify/route.go` (`Route`, `Router`, `LoadRoutes`), a severity rank in `notify`,
  `KindApprovalPending`.
- **Changed**: `controlplane.emit` stamps severity; `RequestApproval` emits; `cmd/openshield-server`
  parses named sinks and an optional `OPENSHIELD_ALERT_ROUTES` table.
- **No migration, no proto change, no new dependency.**
- **Backward compatible**: with no routing table configured, the Router is not installed and delivery is
  the existing fan-out-to-all.
- **Honest scope**: **no templating** — rendering operator-supplied templates over notification fields is
  an injection surface into whatever displays the result, and `Detail` is already a closed-vocabulary
  summary; a per-sink format belongs in the receiver. No escalation ladders, on-call schedules, rotations
  or reminders — those need a schedule model and a time-of-day notion this does not have, and a
  half-built pager rotation is worse than none. No per-sink rate limiting or digesting. Routing matches
  kind and severity only, not subject or entity, because routing on a subject would put a pseudonymous
  identifier into a routing decision an operator reads. Rules are operator configuration validated at
  load, with no UI (PLAT-1).
