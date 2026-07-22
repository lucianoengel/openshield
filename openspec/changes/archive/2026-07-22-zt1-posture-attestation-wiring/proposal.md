## Why

ZT-1 increments 1–3 built the attestation substrate: an authentic, fresh TPM quote (1), an AK proven
genuine-TPM-resident (2), and a PCR policy that gates the attested state against a golden baseline (3) —
all real-swtpm-proven. But none of it touches the live access decision yet. Device posture today is
self-reported booleans signed by the agent's software key: the signature proves *which* agent spoke,
not that its device is genuinely in a trustworthy state. This increment wires the attestation substrate
into the Zero-Trust access path so the gateway can require a device to be **hardware-attested** — and,
critically, sets that `Attested` signal *only* from the gateway's own quote verification, never from a
value the endpoint asserts (a self-asserted `attested=true` would reintroduce the exact problem
attestation exists to solve).

## What Changes

- `core.DevicePosture` gains an `Attested` field (the contract), exposed to policy as
  `input.context.device_posture.attested`, so a ZT access rule can require a hardware-attested device.
- A new `AttestationReport` protobuf message carries a device's quote (nonce + attest blob + signature)
  from endpoint to gateway. Note what it deliberately does **not** carry: a boolean `attested` — that is
  computed by the gateway, not reported.
- A gateway `AttestationVerifier`: per-device enrollment (the AK public key + golden PCR baseline
  established at increment-2 enrollment), a one-shot server-issued **nonce** challenge, and
  `VerifyReport` — which checks nonce freshness, verifies the quote against the enrolled AK (increment
  1), and evaluates the PCR policy against the golden baseline (increment 3). Only a report that passes
  all three marks the device attested.
- The access proxy sets `DevicePosture.Attested` from the verifier (server-verified), so a
  posture-requiring policy admits an attested device and denies an unattested or drifted one.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `device-attestation`: adds server-side verification of a device attestation report (nonce
  freshness + quote + PCR policy), the `Attested` posture signal it produces, and the Zero-Trust access
  path's ability to require a hardware-attested device.

## Impact

- **Code:** `core.DevicePosture.Attested` + policy mapping; a new `AttestationReport` proto (regenerated);
  `gateway.AttestationVerifier`; access-proxy enrichment. Proven end-to-end with a real swtpm quote fed
  through the verifier and a policy that requires attestation.
- **Scope note (honest):** this increment lands the verifier primitive and wires `Attested` into the
  access decision. The physical NATS **challenge/report transport** (a nonce beacon + report channel
  between fleet and gateway) is a follow-up — like earlier ZT increments that shipped the primitive
  (RiskStore, D89) before its transport (D91). The load-bearing security property — `Attested` is
  server-verified, nonce-fresh, and gates access — is delivered and proven here.
- **Completes ZT-1** (core → EK activation → PCR policy → **posture wiring**).
