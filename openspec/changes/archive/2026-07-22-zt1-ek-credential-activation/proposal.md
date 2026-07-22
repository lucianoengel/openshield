## Why

ZT-1 increment 1 shipped the quote generate/verify core, but with a stated gap: a verifier trusts an
Attestation Key (AK) by its raw public key alone. Nothing yet proves that AK lives in a genuine TPM —
an attacker on a compromised host can generate their own software-or-TPM AK and quote faked PCRs under
it. This increment closes that gap by binding the AK to the TPM's **Endorsement Key (EK)** at
enrollment, using TPM credential activation: a challenge the server can only construct for the genuine
EK's public key, which only that EK's TPM — holding the named AK — can answer.

## What Changes

- The endpoint creates an EK in the endorsement hierarchy and presents (EK public, AK public, AK name)
  at enrollment.
- The server (holding **no TPM**) builds a credential-activation challenge with `CreateCredential`:
  encrypt a random secret to the EK's public key, bound to the AK's name.
- The endpoint's TPM runs `TPM2_ActivateCredential` — which succeeds only when the EK and the named AK
  are **co-resident in the same TPM** — and returns the recovered secret.
- The server confirms the returned secret equals the one it issued: proof the AK is bound to that EK,
  i.e. resident in a genuine TPM. A wrong TPM's EK cannot decrypt; a substituted AK breaks the name
  binding.
- This is implemented entirely with `go-tpm` — its `CreateCredential`/`ImportEncapsulationKey` do the
  server-side MakeCredential in pure Go — keeping the D183 decision to avoid `go-tpm-tools` intact. No
  new Go dependency.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `device-attestation`: adds EK-based credential activation, so an AK can be proven resident in a
  genuine TPM (identified by its EK) rather than trusted by raw public key.

## Impact

- **Code:** extends `internal/attest` (EK creation, server-side challenge, endpoint activation). Tested
  against real `swtpm` (single-TPM round-trip succeeds; a second swtpm's EK cannot activate; a
  substituted AK name fails), gated and CI-covered exactly as increment 1.
- **No proto/core change** in this increment — the enrollment wire format and posture wiring are
  increment 4. This increment ships the activation primitive and its proof.
- **Scope:** increment 2 of 4 for ZT-1 (core → **EK credential activation** → measured-boot PCR policy
  → posture wiring).
