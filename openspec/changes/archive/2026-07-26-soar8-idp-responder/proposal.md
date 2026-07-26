## Why

SOAR-7 built the signed Response-Intent seam and gated its publication on four-eyes and a blast-radius
ceiling. D253/D254 enact intents *inside* OpenShield: the gateway blocks flows, the endpoint denies execs,
and both are undone when the intent's TTL lapses. Nothing enacts an intent against an **external** system.

That last step is qualitatively different, and the difference is the whole ticket: disabling a user or
revoking their sessions in an identity provider is **irreversible**. A TTL cannot restore a revoked
session. Every control OpenShield has for intents so far leans on expiry as the undo, and here there is
none — so the controls have to be stronger, not the same.

## What Changes

- **An IdP responder**: an intent subscriber that, for an approved intent, calls a configured identity
  provider to `disable-user` and/or `revoke-sessions`.
- **A per-connector CLOSED verb set.** A connector declares which intent verbs it handles and which
  actions each maps to. A verb outside that set is ignored, not improvised — the same D14 reasoning as the
  Action set, the intent vocabulary and the playbook step registry.
- **Four-eyes ALWAYS, re-checked by the runner.** SOAR-7 gates only *high-impact* verbs at publication.
  The runner requires an approved four-eyes approval bound to the intent id for **every** verb it acts on,
  and re-checks it itself rather than trusting that publication gated it. A component that takes an
  irreversible action on an external system must not delegate its authorization check to the component
  that asked.
- **Migration 034 `runner_actions`**: the durable record linking **intent id → the API call that was
  made** (connector, verb, subject, target, HTTP status, time). Unique on (connector, intent id), so a
  redelivered intent cannot re-disable an account.
- **Claim before calling**, with a visible `claimed` state. For an irreversible external action the row is
  claimed first, so a crash mid-flight leaves a `claimed` row an operator can see rather than a silent
  repeat on redelivery.

## Capabilities

### New Capabilities
- `integration-runners`: off-pipeline execution of approved response intents against external systems,
  over a per-connector closed verb set, with an auditable intent→API-call record.

## Impact

- **New code**: `internal/runner` (the connector, its closed verb set, the outbound call),
  `internal/controlplane/runner.go` (approval re-check, claim, record).
- **Migration 034**: `runner_actions`. Additive.
- **No proto change, no new dependency.**
- Inert unless a connector is configured.
- **Honest scope**: this increment is **SOAR-8(b)**; the ITSM/ticketing half (incident→ticket with status
  sync-back) is increment 2 and is not in this change. No vendor-specific API shapes (Okta, Entra) — a
  generic authenticated JSON connector whose endpoint and token are operator configuration; a vendor
  adapter is a per-vendor addition, not a core concern. **No undo**: a revoked session cannot be
  un-revoked, and intent expiry restores nothing here, which is stated wherever the connector is
  described. No retries (a failed call is recorded and left for an operator; automatic retry of an
  irreversible action is how one failure becomes several). No rollback of a partially-applied multi-action
  verb. No user-identity mapping beyond passing the intent's pseudonymous subject through — resolving a
  pseudonym to a directory account is the deployer's join, and doing it here would put a re-identification
  table in the control plane.
