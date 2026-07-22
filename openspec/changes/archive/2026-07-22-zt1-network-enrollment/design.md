## Context

`attest.NewChallenge(ekPub, akName)` (server, no TPM) and `attest.Activate`/`VerifyActivation` (D184) are
the credential-activation primitives. The verifier's `Enroll(subject, akPub, golden)` is the record. This
increment is the network handshake that connects them: prove the AK genuine, then enroll.

## Goals / Non-Goals

**Goals**
- A two-round-trip enrollment handshake (enroll request → challenge; activation → result).
- `gateway.EnrollmentResponder` (stateful across the two steps) and `posture.Enroll` (endpoint client).
- Prove end to end: a device enrolls over the wire and then attests; a fake device is refused.

**Non-Goals**
- EK-certificate-chain validation (increment-2 scope note).
- Operator-vouched golden baselines (the file-based D189 path stays for that).
- Enrollment authorization/tokens (who may enroll) — the enrollment channel is the mTLS-authenticated
  NATS (D55); an enrollment-authorization policy is a noted follow-up.

## Decisions

### D1 — Two request/reply steps with server-side pending state
Step 1 (`SubjectAttestEnroll`): the device sends `{subject, ek_public, ak_public, ak_name, golden}`; the
gateway builds a challenge with `NewChallenge` and stores a pending record `{ak_public, golden,
expected_secret}` keyed by subject, replying the challenge. Step 2 (`SubjectAttestActivate`): the device
sends `{subject, recovered_secret}`; the gateway looks up the pending record, `VerifyActivation`s, and on
success `Enroll`s the device and clears the pending state. Two request/reply exchanges (the device drives
both) keep it simple; the pending map is the only added state, cleared on success.

### D2 — The activation proves the AK genuine; the golden baseline is trust-on-first-enrollment
The security-critical property is that the AK lives in a real TPM — enforced by the activation (a device
whose EK cannot decrypt the challenge, or whose AK name does not match, cannot recover the secret and is
refused). The golden PCR baseline is captured from the device's reported state at enrollment (TOFU):
sound when enrollment runs in a known-good state (provisioning), and explicitly weaker than an
operator-vouched baseline — stated in the proposal and the decision, with the file-based path (D189)
remaining for operator-vouched baselines.

### D3 — Failures are explicit, never a silent enroll
Every rejection — an unparseable EK, a failed challenge build, no pending record, a mismatched secret —
returns an error in the reply and does NOT enroll. An enrollment only happens after a verified
activation; there is no partial or optimistic enroll.

### D4 — Reuse the existing verifier and primitives unchanged
`EnrollmentResponder` composes `attest.NewChallenge`/`VerifyActivation`/`ParseAKPublicKey` and the
verifier's `Enroll` — no new crypto. The endpoint `posture.Enroll` composes `attest` EK/AK/Activate. This
increment is protocol + wiring over the D184 primitives.

## Risks / Trade-offs

- **TOFU golden baseline** — weaker than operator-vouched; mitigated by running enrollment at
  provisioning and by keeping the file-based path; stated (D2).
- **Pending-state growth / abandoned handshakes** — a device that starts step 1 but never completes step
  2 leaves a pending record; bounded by keying on subject (one pending per subject, overwritten) — a TTL
  sweep is a minor follow-up, noted.

## Migration Plan

Additive: enrollment proto messages (regenerated), one responder, one endpoint client, one binary wiring
block. No verifier or gateway-decision change.

## Open Questions

- Whether to gate enrollment with an authorization token (which devices may enroll) beyond the mTLS
  channel. Deferred; noted with the enrollment-authorization follow-up.
