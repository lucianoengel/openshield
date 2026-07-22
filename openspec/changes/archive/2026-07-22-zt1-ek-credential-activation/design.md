## Context

Increment 1 verifies a quote's signature and freshness against a stored AK public key, but has no way
to know that AK belongs to real TPM hardware. TPM 2.0's answer is the Endorsement Key: a
manufacturer-rooted key unique to each TPM (in production, accompanied by an EK certificate chaining to
the TPM vendor's CA). Credential activation is the challenge-response that ties an AK to an EK: the
verifier encrypts a secret such that only the TPM holding the EK private key, and controlling the named
AK, can recover it.

## Goals / Non-Goals

**Goals**
- Create an EK in the endorsement hierarchy and expose its public key for enrollment.
- Server-side (no TPM): build a credential challenge bound to (EK public, AK name), and verify the
  activated secret.
- Endpoint-side: run `TPM2_ActivateCredential` with the EK and AK to recover the secret.
- Prove against real swtpm: same-TPM activation succeeds; a different TPM's EK cannot recover the
  secret; a substituted AK name fails the binding.

**Non-Goals (later / out of scope)**
- EK **certificate** validation against a TPM-vendor CA — swtpm has no vendor cert; this increment
  proves the AK↔EK binding, and a production deployment adds EK-cert-chain validation as configured
  trust anchors (noted, not built).
- The enrollment **wire format** and persistence (increment 4 / enrollment integration).
- Measured-boot PCR policy (increment 3).

## Decisions

### D1 — Pure-Go server-side MakeCredential via go-tpm's `CreateCredential`
The server has no TPM, so it cannot run the `TPM2_MakeCredential` command. go-tpm ships the pure-Go
equivalent: `ImportEncapsulationKey(ekPublic)` turns the EK public area into a `LabeledEncapsulationKey`,
and `CreateCredential(rand, key, akName, secret)` returns the `(credentialBlob, encryptedSecret)` an
endpoint feeds to `TPM2_ActivateCredential`. This keeps the entire feature inside go-tpm — honoring the
D183 decision to avoid `go-tpm-tools` — with no hand-rolled TPM credential-protection crypto and no new
dependency.

### D2 — EK is the standard ECC-P256 endorsement template
Use go-tpm's `ECCEKTemplate` (the TCG reference ECC EK). Its standard auth **policy** is
`TPM2_PolicySecret(endorsement)`, so using the EK in `ActivateCredential` requires a policy session that
executes that command; the endpoint side runs it (mirroring go-tpm's `ekPolicy` helper). The EK is a
decryption key (it protects the credential seed), distinct from the AK (a restricted signing key).

### D3 — The AK↔EK binding is the trust upgrade, not EK-cert validation
This increment proves the AK is **co-resident with the EK** in one TPM. In production the EK's identity
is anchored by its EK certificate (vendor-signed); swtpm has none, so the tests assert the binding
property (same TPM ✓, different TPM ✗) rather than a cert chain. `VerifyActivation` is a constant-time
comparison of the issued and recovered secret — the server's confirmation step; the cryptographic work
is enforced by the TPM in `ActivateCredential`.

### D4 — Reuse the increment-1 AK unchanged
`CreateAK` from increment 1 is unchanged; activation binds whatever AK the endpoint presents, by its
name, to the EK. This keeps the two increments composable: increment 1 proves quote authenticity under
an AK; increment 2 proves that AK is genuine-TPM-resident.

## Risks / Trade-offs

- **No EK-cert chain here** → a caller that skips production EK-cert validation would accept any EK,
  including a software EK. Mitigated by stating it in the proposal/design/decision and scoping cert
  validation as the production enrollment step; the binding proof itself is real and swtpm-tested.
- **EK policy-session friction** → the endpoint must run a `PolicySecret(endorsement)` session to use
  the EK; encapsulated in an `Activate` method so callers don't hand-manage sessions.

## Migration Plan

Additive to `internal/attest`; no schema/proto/core change. Nothing external depends on it yet.

## Open Questions

- Whether to also support an RSA-2048 EK (some TPMs ship only an RSA EK cert). ECC-P256 is universal on
  TPM 2.0; RSA EK support can follow when EK-cert validation lands.
