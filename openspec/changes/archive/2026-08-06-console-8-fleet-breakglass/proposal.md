# CONSOLE-8 · Fleet inventory + break-glass surface

## Why

`INVARIANTS.md:131`: *"'How do I stop this?' is the question a CISO asks before 'what does it detect?'"*

The product can be stopped fleet-wide. `PublishFleetControlSeq`
(`internal/controlplane/fleetcontrol.go:88`) signs a `FLEET_VERB_ENFORCEMENT_DISABLE`, gates it behind an
always-required four-eyes approval, gives it a mandatory TTL, and publishes it. **It then records nothing
about having done so.**

The control carries `issued_at`, `expires_at` and `reason` on the wire, and every one of them is discarded
after `proto.Marshal`. What survives in the database is a bare counter
(`config_settings.__fleet_control_sequence`) and the approval row. So the question an operator asks the
moment they find enforcement off —

> since when, by whom, until when, and why?

— is answerable **only for "by whom"**, and only by knowing to reconstruct the control id and look it up in
`approvals` by hand.

The mirror half is no better. `agent_enforcement` (PLAT-9) answers *which agents report themselves
disabled*, and its schema comment is explicit that this deliberately merges two causes: an agent disabled
by a fleet control and an agent disabled by its own local break-glass file report identically. That is the
right choice for the agent's state and the wrong one for the fleet view, because with no record of what was
SENT there is nothing to compare the reports against. An operator cannot tell "my disable arrived" from
"seventeen hosts turned themselves off".

There is also no roster surface at all. `/overdue` lists silent agents; nothing lists the fleet.

## What Changes

- **`fleet_controls`** — a new table written at publish time, recording what only that moment knows:
  `control_id`, `verb`, `sequence`, `issued_at`, `expires_at`, `reason`. Written INSIDE
  `PublishFleetControlSeq`, after the approval gate and before the publish, so a control that reaches the
  wire cannot be one that was never recorded.
- **`GET /fleet/controls`** — the break-glass register. Every control issued, whether it is still standing
  (its TTL has not lapsed and no later control supersedes it), and the four-eyes pair that authorized it,
  joined from `approvals`.
- **`GET /fleet`** — the roster: every enrolled agent, its enrollment and revocation, its last VERIFIED
  telemetry, how long it has been silent, and its self-reported enforcement state with the fleet sequence
  it has applied.
- **`fleetSuppressed`** — the derived answer to "is enforcement suppressed by fleet control right now",
  computed as the highest-sequence unexpired control being a DISABLE, so a later RESTORE and a lapsed TTL
  both end suppression.

## Impact

- Affected specs: `enforcement` (the break-glass register and its invariants), `control-plane` (the two
  routes and their tier).
- Affected code: `internal/controlplane/fleetcontrol.go`, new `internal/controlplane/fleet.go`, new
  migration `051_fleet_controls.sql`, `internal/controlplane/operator_read.go`,
  `internal/controlplane/enroll_http.go`.
- No proto change. No behaviour change to what agents receive or how they act on it.

## Deliberately NOT in this increment

The ticket also names *platform, version, attestation verdict + TTL, posture, spool depth*. **None of these
is data this platform collects**, and each is a separate increment with its own cost. Naming them here so
they are a decision rather than an omission:

- **platform / version** — `Heartbeat` (`proto/openshield/v1/heartbeat.proto`) has five fields and none is
  either; `agent_version` appears nowhere in the tree. This needs additive proto fields, agent-side wiring
  and a projection. Cheap and worth doing; it is increment 2.
- **spool depth** — the agent's durable queue (`internal/transport/queue`) knows its own depth and never
  reports it. Same shape as above: a heartbeat field. Increment 2.
- **attestation verdict + TTL** — lives in the GATEWAY's in-memory `AttestationVerifier`
  (`internal/gateway/attestation.go`), in a different process, and is deliberately not persisted. Surfacing
  it in the control plane means a transport, not a query.
- **posture** — lives in the gateway's in-memory `PostureStore`, keyed by the **pseudonymous subject**
  (D23), not by `agent_id`. Joining posture to the agent roster would re-identify the subject the
  pseudonym exists to protect. This is a privacy boundary, not an oversight, and it must be argued rather
  than joined.

Shipping empty `platform` / `spool_depth` fields that nothing writes would be the unwired-field defect this
repo has now found six times (D313, D415, D417, D418, D456, D470). They are absent on purpose.
