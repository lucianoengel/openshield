## Why

SOAR-8's second half, and the last item in Lane B. An incident is raised, paged, enriched, playbook-run
and measured — and the team that actually does the work tracks it in a ticketing system nobody here talks
to. So the incident and the ticket drift: the incident stays `open` in OpenShield forever because closing
it is a second, manual step nobody remembers.

SOAR-8(b)'s design left one question open, and this change answers it: whether ITSM shares the
`runner_actions` table. It does not — see below.

## What Changes

- **Incident → ticket.** A matching incident opens exactly one ticket in the configured ITSM, recorded
  with the remote reference so the two are linked in both directions.
- **Status sync-back.** The ticket's status is polled; a status the connector declares as *closed*
  transitions the incident to `closed`, attributed to the connector (`itsm:<name>`), never to a human who
  did not do it.
- **A CLOSED set of remote statuses that mean closed.** A status the connector does not declare is
  **ignored**, never assumed to mean closed. Closing an incident because a remote system returned a word
  we do not understand is how an incident stops being investigated.
- **Forward-only is preserved.** A reopened ticket does **not** reopen the incident. D250 made the
  lifecycle forward-only so MTTA/MTTR stay measurable, and an incident needing reopening becomes a *new*
  incident — a rule an external system does not get to override.
- **Its own table** (`itsm_tickets`, migration 035), not `runner_actions`. The two have opposite
  semantics: `runner_actions` is an append-only record of **irreversible, at-most-once, never-retried**
  acts; a ticket is a **mutable, retryable, bidirectionally-synced** object. Sharing one table would force
  one set of semantics onto both and quietly weaken the stronger one.
- **No four-eyes here.** Opening a ticket is not an irreversible action against a person; requiring an
  approval for it would train operators to click through approvals, which is exactly what makes the
  approval on the IdP responder meaningful.

## Capabilities

### Modified Capabilities
- `integration-runners`: adds ticket creation, the closed remote-status vocabulary, and status sync-back
  that respects the forward-only incident lifecycle.

## Impact

- **New code**: `internal/runner/itsm.go`, `internal/controlplane/itsm.go`.
- **Migration 035**: `itsm_tickets`. Additive.
- **No proto change, no new dependency.** Inert unless a connector is configured.
- **Honest scope**: **polling, not a webhook** — sync-back latency is one poll interval; a webhook would
  be faster but needs an authenticated inbound route a third-party SaaS can reach, which is a new trust
  boundary and a decision of its own. No vendor API shapes (Jira, ServiceNow): a generic authenticated
  JSON connector; a vendor adapter is a per-vendor addition. Only `closed` is synced back — intermediate
  ITSM states are not mapped onto `triaged`/`contained`, because those mean specific things here and
  guessing a mapping would corrupt the metrics SOAR-6 derives. No comment/worklog sync. No ticket
  reassignment or field updates from OpenShield after creation. The ticket carries the incident's
  pseudonymous subject and closed-vocabulary metadata only — never evidence content.
