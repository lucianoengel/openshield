## Why

File-based enrollment (D189) works, but it trusts the operator's manual capture of a device's AK — the
gateway never re-proves that AK belongs to genuine TPM hardware. The credential-activation primitive
(D184) can prove exactly that over the wire, but it was only ever exercised in tests. This increment
wires it into a live enrollment handshake: a device proves its AK is resident in a real TPM, and only
then does the gateway record its enrollment — no operator file, and the genuine-TPM proof is enforced at
enrollment time.

## What Changes

- A two-step enrollment handshake over NATS: the device sends its EK, AK, and PCR state; the gateway
  replies with a credential-activation challenge (encrypt a secret to the device's EK, bound to its AK
  name); the device activates it with its TPM and returns the recovered secret; the gateway confirms the
  secret and enrolls the device — the AK proven genuine-TPM-resident by the activation.
- A gateway `EnrollmentResponder` (serve the challenge, verify the activation, enroll) and an endpoint
  `posture.Enroll` client (run the handshake).
- The gateway binary serves enrollment when configured.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `device-attestation`: adds automated network enrollment — a device proves its AK genuine-TPM-resident
  via credential activation and is enrolled without an operator-distributed file.

## Impact

- **Code:** enrollment-handshake proto messages (regenerated); `gateway.EnrollmentResponder`;
  `posture.Enroll`; gateway-binary wiring. Proven with real swtpm + embedded NATS: a device enrolls over
  the wire and can then attest; a device that cannot activate the challenge (a different TPM's EK) is
  refused enrollment.
- **Scope note (honest):** the automated flow proves the **AK genuine** (the security-critical part) and
  records the device's **current PCR state as its golden baseline** — trust-on-first-enrollment: sound
  only when enrollment happens in a known-good state (e.g. provisioning). An operator who wants to vouch
  for a specific baseline out-of-band keeps the file-based path (D189). EK **certificate**-chain
  validation (anchoring the EK's identity to a TPM vendor CA) remains the increment-2 scope note. This
  completes ZT-1's automated enrollment; the operator-vouched and cert-anchored variants are documented
  alternatives/follow-ups.
- Removes the manual file-capture step from the ZT-1 enrollment path.
