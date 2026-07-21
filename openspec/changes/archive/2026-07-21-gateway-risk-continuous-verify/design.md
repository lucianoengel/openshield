## Context

Peer-UEBA (D53/D54) computes a per-subject risk score server-side, but it is a one-way
dead end — D54 states plainly "no risk is fed back". The access broker (D87) authorizes
on the identity context (D85), which ALREADY has a `RiskScore`/`HasRiskScore` field
(D53) — nothing fills it at the gateway. This closes the loop under the T2 model the
owner confirmed: the server publishes risk as DATA; the gateway's LOCAL policy decides.

## Goals / Non-Goals

**Goals:** the gateway reads published per-subject risk and the local policy step-ups/
denies on it (continuous verification), decided locally.

**Non-Goals:** the server→gateway publish channel (A.5b); a STEP_UP action; the posture
producer; egress-path risk.

## Decisions

**Risk is DATA the gateway reads; the LOCAL policy decides — the server never actuates
(T2/D14).** The `RiskStore` holds the latest published risk per subject; the access
handler enriches the identity Context with it; the policy makes the call. A compromised
server can publish a WRONG risk score (lie), which the local policy still evaluates
within its bounded action set — it cannot COMMAND the gateway to cut access. This is
exactly the property that lets continuous verification exist without reopening the D14
control-plane-actuates threat: the server informs, the gateway decides.

**Absent risk is NOT high — the opposite fail-direction from posture.** D85 established
that absent posture fails CLOSED (deny) — an unattested device is untrusted. Absent RISK
fails OPEN in the sense that no risk means "analytics is quiet", not "danger" — denying
every subject whenever the risk feed is down would be a fleet-wide outage on an analytics
hiccup (the D28 fail-open-with-no-signal trap in reverse). So `HasRiskScore` distinguishes
the two, and the policy decides: it denies on HIGH risk (present and >= threshold), and a
missing score does not itself deny. Posture and risk are both enrichment, both expose
their absence (D28), but the safe direction differs because they mean different things —
"is this device trusted" (deny if unknown) vs "is this subject anomalous" (don't deny on
silence).

**Reuse BLOCK/REDIRECT — no new action.** A high-risk verdict is deny (BLOCK) or step-up
(REDIRECT to re-auth, D69). Both exist. A dedicated STEP_UP verb (finer than REDIRECT) is
a T1 option the owner can take later; A.5 needs no action-set change.

## Risks / Trade-offs

- **Subject-space unification.** Peer-UEBA scores the endpoint file-event subject; the
  gateway's subject is the client-identity pseudonym. For risk to gate access, the two
  must resolve to the same subject — an identity-mapping/deployment concern. A.5 proves
  the mechanism keyed on the identity subject; unifying the spaces is a deployment step.
- **Staleness.** The RiskStore holds the last published value; a subject whose risk just
  spiked is only cut once the publish arrives. Near-real-time via the signed channel
  (A.5b); the store always reflects the latest received, never a stale cache with no
  refresh. Noted.
