## Context

D85's DevicePosture has a HasPosture flag: absent posture fails CLOSED. But nothing
filled posture — it was always absent, so a posture policy denied everyone. This adds
the source, mirroring the risk channel (D91): a PostureUpdate is published, the gateway
populates a PostureStore, the access proxy enriches DevicePosture.

## Goals / Non-Goals

**Goals:** the gateway reads published device posture and enriches the access context;
an unattested device fails closed.

**Non-Goals:** the endpoint's posture-report side; per-message signing; OIDC.

## Decisions

**Posture mirrors risk (D91), but fails in the OPPOSITE direction (D85).** Same shape —
a published update, a store, an access-proxy enrichment. But absent RISK is not high
(don't deny on analytics silence), while absent POSTURE is untrusted (DENY — an
unattested/tampered device). The PostureStore's `Get` returns has=false for an unknown
subject, and the enrichment leaves `HasPosture=false`, so a policy requiring
`device_posture.has_posture` denies it. This is the tamper-lockout made real: a killed
endpoint reports no posture and is denied at the gateway.

**The gateway consumes posture; the endpoint produces it — the report side is a
follow-up.** The endpoint agent knows its own device state (disk encryption, patch
level, agent presence) and is the authority on it (it cannot be trusted to LIE in its
favour, but a compromised endpoint that reports "compliant" while tampered is exactly
why the SERVER should attest posture in a hardened deployment — noted). This increment
builds the gateway consumption + store + enrichment; the report/attestation side is the
next step.

## Risks / Trade-offs

- **Self-reported posture is only as trustworthy as the reporter.** A rooted endpoint
  could report "compliant". True device attestation (TPM/secure-boot measured posture)
  is the hardening; self-report is the honest first step, and the absent-posture
  fail-closed still catches an endpoint that stops reporting entirely.
- **Subject-space unification** (as with risk, D91): posture keyed on the same subject
  as the identity; unifying endpoint and gateway subject spaces is a deployment concern.
