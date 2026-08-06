# Design — CONSOLE-8 increment 1

## The record is written where the control is minted, not where it is asked about

`fleet_controls` is written inside `PublishFleetControlSeq`, between the four-eyes gate and
`conn.Publish`. Three orderings were possible and only one is defensible:

- **Before the approval gate** — records controls that were refused. The register would then list disables
  that never happened, which is worse than no register.
- **After the publish** — a publish that succeeds and a write that fails leaves enforcement suppressed
  across the fleet with nothing recording it. That is the exact state this change exists to abolish.
- **Between them (chosen)** — a recorded control might fail to publish, so the register can name a control
  the fleet never received. That is the safe direction of error: it over-reports suppression, and an
  operator who investigates finds `agent_enforcement` showing every agent still enforcing. The alternative
  under-reports it.

The write is therefore **fatal to the publish**: if the record cannot be written, the control is not sent.
This is deliberate and is the opposite of `recordEnforcementState`, which is best-effort because a
heartbeat's purpose is liveness and must not be lost to a projection failure. A fleet disable has no such
competing purpose — refusing to turn the product off because we cannot say we did is the correct trade.

## "By whom" is the approval pair, not a publisher

`PublishFleetControlSeq` is reached from `openshield-server fleet-control publish`, an **operator-local
CLI** (D51: credential-minting and fleet control are operator-local, not network routes). There is no HTTP
principal in scope and no authenticated identity to record. Recording an `issued_by` would mean inventing
one — the OS user, or a constant — and a name in an audit trail that nothing verified is worse than no
column, which is the D46/SEC-D argument the `approvals.assurance` column already makes in this codebase.

So the register does not store an actor. It **joins** `approvals` on
`(subject_kind = 'fleet-control', subject_id = control_id)` and reports the `requester`, `approver` and
`assurance` that four-eyes already recorded and verified. Those are the two names that authorized the
suppression, which is what "by whom" means for an action that requires two people.

A `RESTORE` has no approval — restoring enforcement is not gated, by design — so its pair is absent, and
the surface reports that as absent rather than empty-string.

## Suppression is derived, never stored

There is no `suppressed` boolean. The register stores controls; whether the fleet is currently suppressed
is computed the same way a consumer computes it (`internal/intent/fleetcontrol.go:184`):

> the highest-sequence control whose `expires_at` is still in the future; suppression holds if that control
> is a DISABLE.

Two properties fall out of computing rather than storing it, and both are requirements:

1. **A lapsed TTL ends suppression with no writer.** The proto comment is explicit that a consumer treats
   an expired control as absent. A stored boolean would need a sweeper to agree with the fleet, and a
   sweeper that falls behind makes the console lie in the most dangerous direction — reporting protection
   that is off as on, or off as on.
2. **A later RESTORE wins over an earlier DISABLE.** Ordering is by `sequence`, not by `issued_at`, because
   sequence is what consumers order by. Ordering the console by wall-clock time while agents order by
   sequence would let the two disagree under clock skew.

## Tier: ANALYST for both, argued

`/fleet` and `/fleet/controls` sit at **analyst**, the broadest read tier. The uncomfortable half of that
is real and worth stating: a list of which endpoints are not enforcing is a target list, and the threat
model names a malicious insider holding an operator role.

It is still right, for two reasons:

- **The roster is already at this tier.** `/overdue` returns every enrolled agent id and how long it has
  been silent — the same target list, by absence instead of by suppression. Putting the roster behind a
  higher tier while `/overdue` stays open would be a gate with a door beside it.
- **An analyst who does not know a host was not enforcing will misread its evidence.** An alert from a
  suppressed host means something categorically different from the same alert on a protected one. Hiding
  suppression from the tier that triages alerts does not protect the fleet; it produces wrong conclusions
  about it.

The break-glass register is oversight of an action two named people already took. Restricting who may read
it weakens the control rather than the exposure.

## Never-seen is `null`, not the zero time

`last_seen` for an enrolled agent with no verified telemetry serializes as `null`. The `LastSeen` method
already draws this distinction in Go (`*time.Time`, nil = never seen) precisely so a database error cannot
masquerade as agent absence (SEC-11). Serializing `0001-01-01T00:00:00Z` would put that distinction back
in the console's hands as a magic-value check, and "silent for 2025 years" is the kind of field a reader
learns to ignore.

## Contradiction with the archived spec store: none found

`openspec/specs/enforcement/spec.md` carries the PLAT-9 acknowledgement requirements. Nothing there
asserts that issued controls are recorded, so this adds rather than contradicts. No requirement is
weakened.
