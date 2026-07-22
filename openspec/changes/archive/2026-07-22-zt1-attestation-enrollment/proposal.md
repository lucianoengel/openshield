## Why

The attestation transport (D188) drives the gateway's verifier on live data, but the verifier starts
empty: nothing populates it with the devices it should trust. Until it holds each device's AK public
key and golden PCR baseline, every device is unenrolled and every attestation fails closed — the whole
ZT-1 chain is runnable but inert. This increment adds enrollment distribution: capture a device's trust
anchors and load them into the gateway's verifier, so real devices can attest end to end.

## What Changes

- An `AttestationEnrollment` record — a device's subject, AK public key, and golden PCR baseline — with a
  JSON file format an operator distributes to the gateway (consistent with how the posture roster is
  distributed).
- An endpoint helper that builds a device's enrollment record from its TPM (marshal the AK public,
  capture the golden PCRs).
- A gateway loader that reads the enrollment file and enrolls each record into an `AttestationVerifier`,
  failing closed on a malformed or incomplete record (never a silent skip).
- The gateway binary loads enrollments before serving, so a loaded device attests over the live channel
  exactly as a programmatically-enrolled one does.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `device-attestation`: adds enrollment distribution — capturing a device's AK + golden baseline and
  loading them into the gateway verifier.

## Impact

- **Code:** an `AttestationEnrollment` record + JSON (de)serialization; `posture.BuildEnrollment`
  (endpoint) and `gateway.LoadAttestationEnrollments` (gateway); gateway-binary wiring. Proven with real
  swtpm: a record built from a device, written, and loaded yields a verifier that attests that device end
  to end — identical to a programmatic enrollment.
- **Scope note (honest):** this is **file-based** distribution — the operator captures a known-good
  device's record and distributes it, and the loader trusts that capture (exactly as the posture roster
  trusts the operator). The record represents a device whose AK was proven genuine by credential
  activation (D184) at capture time; an **automated network enrollment** that runs live credential
  activation over the wire and records the result is the larger follow-up. The endpoint re-attestation
  loop inside a running fleet-agent remains deployment wiring.
- Makes the ZT-1 attestation chain runnable with real devices — the enrollment gap D186/D188 named.
