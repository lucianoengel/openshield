## Why

Increment 4 built the gateway's `AttestationVerifier` — enroll, issue a nonce, verify a report — and
wired `DevicePosture.Attested` into the access decision. But nothing carries the challenge and the
report between a device and the gateway, so the verifier is a wired-but-inert primitive (exactly where
`RiskStore` sat at D89 before its transport landed at D91). This increment adds that transport: a device
requests a fresh nonce, quotes over it, and publishes the report; the gateway issues the nonce and
verifies the report, flipping the device to attested on the live channel.

## What Changes

- Two NATS subjects: an attestation **challenge** (request/reply — a device asks for a fresh nonce) and
  an attestation **report** (a device publishes its quote).
- A gateway `AttestationResponder`: answers challenge requests from the verifier's `Challenge`, and
  subscribes to reports, running each through `VerifyReport` (dropping and counting failures, like the
  risk/posture subscribers).
- An endpoint client `posture.Attest`: request a nonce, produce a TPM quote over it (increment 1),
  publish the `AttestationReport`.
- The report needs **no extra signature layer** — it *is* a TPM-signed quote, which authenticates
  itself against the enrolled AK; a forged report simply fails `VerifyReport`.
- The gateway binary starts the responder when NATS and a verifier are configured.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `device-attestation`: adds the challenge/report transport that drives the verifier on live data — a
  device attests over NATS and the gateway marks it attested.

## Impact

- **Code:** two `natsx` subjects; `gateway.AttestationResponder`; `posture.Attest` (endpoint client);
  gateway-binary wiring. Proven end-to-end with an embedded NATS server + a real swtpm quote: a device
  requests a challenge, quotes, publishes, and the gateway flips it to attested; a stale/forged report
  is rejected and counted.
- **Scope note (honest):** the responder drives an *already-enrolled* verifier. **Enrollment
  distribution** — populating the verifier with each device's AK public key and golden PCR baseline
  (the output of increment-2 credential activation) — is a separate operational mechanism (like the
  posture roster), a noted follow-up; and the endpoint's periodic re-attestation *loop* inside a running
  fleet-agent binary is deployment wiring. This increment lands the transport and proves the live
  round-trip.
- Completes the ZT-1 operability gap noted in increment 4.
