## Context

The signed-telemetry path (T-017) already verifies Ed25519 signatures before persisting; the
risk/posture channels did not. The fix mirrors the D100 signed-rule-bundle pattern
(verify-before-parse) which this project already trusts.

## Goals / Non-Goals

**Goals:** authenticate risk (control-plane key) and posture (publisher key) per-message,
fail-closed, with the drop observable.

**Non-Goals:** the signed posture producer (HON-4); per-subject posture binding; JetStream.

## Decisions

**Verify before parsing the inner update.** `verifySignedUpdate` checks the Ed25519 signature
against the trusted key BEFORE the RiskUpdate/PostureUpdate is unmarshaled — an unverified
update's contents never reach the store, exactly as D100 verifies a rule bundle before
compiling it.

**No trusted key → no subscription (fail-closed).** The gateway binary subscribes to a channel
ONLY when its trusted key is configured. It never falls back to applying unsigned updates, so
a deployment that forgets the key gets an inert channel (risk allows on absent, posture denies
on absent) — never a forgeable one.

**Risk vs posture have different key authorities.** Risk is published by the control plane →
verified against the control-plane key. Posture is agent-self-reported → verified against the
publisher key. Same envelope, different trusted key. Posture's per-subject binding (subject ==
signing agent) is deferred to HON-4 where the producer exists to test it.

**Reject and COUNT, never drop silently.** Each subscriber exposes a `Rejected` counter, so a
forged-update flood is observable — the same no-silent-loss discipline as telemetry gaps.

## Risks / Trade-offs

- **The control-plane signing key is a new trust root.** It joins the CA / escrow / witness
  keys; guard it (D16). A leaked risk key lets an attacker forge risk — but that is a far
  higher bar than "any publisher", which was the bug.
- **Posture happy-path is untested until HON-4.** Honest: the producer does not exist yet;
  the reject path is what protects today.
