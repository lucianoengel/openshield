## Why

An endpoint can now attest (D188) and be enrolled (D189), but `posture.Attest` is a single shot — it
proves the device's state at one moment. Zero Trust is *continuous* verification: a device that was
compliant at login but drifts (a bootkit, an unexpected kernel) must lose its trusted status, not keep
it until the next login. This increment adds the endpoint re-attestation loop: a device re-attests on an
interval, so the gateway's `Attested` signal tracks the device's *current* state, and a drift drops it
within one cycle.

## What Changes

- `posture.AttestLoop`: attest once immediately, then re-attest on an interval until the context is
  cancelled (built on the existing `retain.Loop` ticker). Errors are logged best-effort, never fatal —
  a transient failure just means the device is briefly unattested (fail closed), and the next cycle
  recovers.
- The fleet-agent starts the loop when attestation is configured (a TPM AK + the PCR set), so a deployed
  device stays continuously attested.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `device-attestation`: adds continuous re-attestation from the endpoint, so the gateway's attested
  signal tracks the device's current state and a drift drops it within a cycle.

## Impact

- **Code:** `posture.AttestLoop` (endpoint loop) + fleet-agent wiring. Proven with real swtpm + embedded
  NATS: the loop keeps a good device attested across cycles, and after the device's PCR state drifts the
  gateway rejects the next re-attestation and the device loses its attested status — continuous
  verification, not a one-time check.
- **Scope note (honest):** the loop re-attests an *already-enrolled* device (D189). The **automated
  network enrollment** (live credential activation over the wire, versus the file-based distribution)
  remains the last ZT-1 operability follow-up. With this increment the live loop — enroll → attest →
  re-attest → policy-gate — is complete for real devices.
