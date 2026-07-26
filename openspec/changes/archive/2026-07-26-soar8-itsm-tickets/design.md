## Context

SOAR-8(b) shipped the IdP responder and recorded one open question: *"whether the ITSM half should share
`runner_actions` (it is not irreversible and wants retry) or get its own table — resolved in increment 2,
once its retry semantics are decided rather than guessed."* This change resolves it.

The incident lifecycle is forward-only (D250) and `TransitionIncident` already refuses a backward move and
stamps the acknowledgement on the first move off `open` (D258). Both matter here: an external system is
about to drive that lifecycle.

## Goals / Non-Goals

**Goals:** one ticket per incident, a closed remote-status vocabulary, sync-back that closes an incident,
attribution to the connector, forward-only preserved.

**Non-Goals:** webhooks; vendor API shapes; mapping intermediate ITSM states; comment/worklog sync; field
updates after creation; four-eyes on ticket creation.

## Decisions

### Its own table, because the semantics are opposite

`runner_actions` records **irreversible, at-most-once, never-retried** acts: the claim is taken before the
call precisely so a redelivery cannot repeat it, and there is deliberately no retry. A ticket is the
reverse — **mutable, retryable, and synced in both directions** — and its row is updated on every poll.

Putting both in one table would force one set of semantics onto the other. The dangerous direction is
obvious: relaxing `runner_actions` to allow updates and retries, to accommodate tickets, would weaken the
guarantee protecting the irreversible half. So: `itsm_tickets`, keyed `(connector, incident_id)`.

### Polling, not a webhook

A webhook is lower-latency and is what most ITSMs offer. It also requires an authenticated inbound route
that a third-party SaaS can reach — a new trust boundary, and one that cannot use the operator-mTLS gate
every other route here sits behind (D55/D58). Polling needs no inbound surface at all and reuses the
leader-only loop shape.

The cost is honest and bounded: sync-back lags by up to one poll interval. That is stated rather than
hidden, and a webhook remains a later decision on its own merits rather than something smuggled in here.

### A closed set of remote statuses means closed — everything else is ignored

`Connector.ClosedStatuses` is the declared vocabulary. Anything else is ignored, and specifically **not**
treated as closed. The failure this prevents is the one that matters: if a remote system renames a status,
or returns something unexpected, the fail-safe direction is "keep investigating", not "stop".

Only `closed` is synced. Mapping intermediate ITSM states onto `triaged`/`contained` would be guessing —
those states mean specific things here, and SOAR-6 derives response metrics from their timestamps, so a
wrong mapping does not just mislabel an incident, it corrupts the measurements.

### Forward-only survives contact with an external system

`TransitionIncident` already refuses a backward move, so a reopened ticket cannot reopen its incident.
That is inherited rather than re-implemented, and it is the right answer: D250 made the lifecycle
forward-only so MTTA/MTTR stay measurable, and an incident that needs reopening becomes a new one. An
external system does not get to override an invariant the metrics depend on.

The sync therefore treats a backward transition as a no-op rather than an error — the ticket reopening is
a legitimate thing for a human to do, it simply does not move this incident.

### The connector is the actor

Sync-back passes `itsm:<name>` as the operator. `TransitionIncident` stamps the acknowledgement on the
first move off `open` (D258), so an incident that goes straight from `open` to `closed` via a ticket would
otherwise record a *person* as having acknowledged it. Recording a machine's decision under a human's name
is a corrupted audit trail, and here it would also corrupt the acknowledgement attribution that response
metrics rest on.

### No four-eyes on ticket creation

Opening a ticket is not an irreversible action against a person. Requiring an approval for it would train
operators to click through approvals — which is precisely what would make the approval on the IdP
responder (D260) meaningless. Gating is reserved for what it is for.

## Risks / Trade-offs

- **Sync lag of one interval** → bounded, stated; a webhook is a separate decision.
- **A remote status vocabulary change stops closing incidents** → fail-safe direction; the ticket row
  records the last observed status, so an operator can see the unmapped value.
- **An ITSM outage stalls sync** → the ticket row keeps its last state and the next tick retries; unlike
  the IdP path, retry IS appropriate here because the operations are idempotent.
- **A ticket carries a pseudonym a deployer cannot resolve** → the same honest limit as D260's IdP
  connector, and the same reason (no re-identification table in the control plane).

## Migration Plan

Migration 035 adds `itsm_tickets` only; inert unless a connector is configured.

## Open Questions

- Whether a webhook receiver belongs on the operator-mTLS surface or needs its own authenticated,
  internet-reachable endpoint — deferred, and explicitly not decided by shipping polling.
