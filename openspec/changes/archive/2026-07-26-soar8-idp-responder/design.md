## Context

`internal/intent` already verifies signed intents and holds the current one per subject — both the gateway
and the endpoint consume it as policy context. `controlplane.PublishIntents` gates publication of
high-impact verbs on a four-eyes approval bound to the intent id, and refuses an over-broad blast radius as
a whole. SOAR-3's approvals are keyed `(subject_kind, subject_id)`, so `("response-intent", <intent id>)`
is already the shape a runner needs to look up.

What does not exist is anything that acts on an intent OUTSIDE OpenShield.

## Goals / Non-Goals

**Goals:**
- Execute approved intents against a configured identity provider: `disable-user`, `revoke-sessions`.
- A per-connector closed verb→action mapping.
- Four-eyes required for every executed verb, re-checked by the runner.
- A durable intent-id → API-call record, unique per (connector, intent).

**Non-Goals:**
- The ITSM half of SOAR-8 (increment 2).
- Vendor API shapes. A generic authenticated JSON connector; a vendor adapter is a per-vendor addition.
- Retries. A failed irreversible call is recorded and left for a human.
- Undo, compensation, or rollback of a partially-applied multi-action verb.
- Resolving the pseudonymous subject to a directory account (see below).

## Decisions

### Four-eyes is re-checked here, and required for verbs publication does not gate

`PublishIntents` gates only `HighImpactVerb`s. `ELEVATE_SCRUTINY` is deliberately ungated there, because
gating everything trains operators to rubber-stamp — correct for a signal a local policy interprets.

It is not correct for a runner. This component reaches into an external identity provider and takes an
action expiry cannot undo, so it requires an approved approval for the intent id **whatever the verb**, and
it looks that approval up itself. Trusting that publication gated it would mean the authorization check
lives in the component that *asks* for the action rather than the one that *performs* it — and any path
that delivers an intent to the runner without going through `PublishIntents` would bypass the check
entirely.

The approval is bound to the intent id, so approval to revoke trust for one subject can never authorize
another. That is the property SOAR-3's `(kind, id)` keying exists for.

### Claim before calling, and leave the claim visible

An irreversible external action needs at-most-once, not at-least-once. The row is inserted
`ON CONFLICT (connector, intent_id) DO NOTHING` **before** the HTTP call; if the insert claims nothing, the
intent was already handled and the call is skipped.

The cost is real and is not hidden: a crash between the claim and the call leaves an action that was never
performed and will not be retried. So the row carries a state — `claimed` → `executed` | `failed` — and a
row stuck in `claimed` is exactly the visible artifact an operator needs. The alternative (call, then
record) makes a crash repeat the action on redelivery, which for "disable this account" is the failure that
gets a SOAR turned off.

### The closed verb set lives on the connector, not in the caller

`Connector.Actions map[IntentVerb][]Action` with `Action` a closed type (`disable-user`,
`revoke-sessions`). A verb absent from the map is ignored and produces no record: the connector declares
what it handles, and "no mapping" is a legitimate answer, not an error to route around. A test asserts the
action vocabulary is exactly those two, so a third cannot be added without changing an assertion that says
why the set is closed.

### The subject passes through as the pseudonym

The intent's subject is a pseudonymous id (D23). The runner sends it as-is and does not resolve it to a
directory account. Resolving it would require a pseudonym→identity table inside the control plane — a
re-identification surface the whole design avoids — so the join belongs to the deployer, in the receiver
they configure. The honest consequence: the connector is only useful where that receiver can do the
mapping, which is stated rather than glossed.

### Irreversibility is documented at the point of configuration

Every other enactment in the platform is restored when the intent lapses (D253/D254 both prove TTL
restoration in tests). An operator's reasonable generalisation is therefore wrong here. The spec, the code
comment and the startup log all say it: expiry restores nothing.

## Risks / Trade-offs

- **A claimed-but-uncalled action is silently ineffective** → visible as a `claimed` row; not auto-retried
  on purpose.
- **A compromised approver plus a compromised publisher can disable accounts** → four-eyes bounds this, it
  does not prevent it; signing proves origin, not authority (the same limit recorded for SOAR-7).
- **The receiver must map pseudonym→account** → stated; the alternative is worse.
- **No retry means a transient IdP outage drops the action** → recorded as `failed` with its cause, for a
  human. Automatic retry of an irreversible call is how one failure becomes several.

## Migration Plan

Migration 034 adds `runner_actions` only. The runner is inert unless a connector is configured, so
deploying the migration and binary changes nothing on its own.

## Open Questions

- Whether the ITSM half should share `runner_actions` (it is not irreversible and wants retry) or get its
  own table — resolved in increment 2, once its retry semantics are decided rather than guessed.
