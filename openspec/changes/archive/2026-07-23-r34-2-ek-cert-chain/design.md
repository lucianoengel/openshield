## Context

`handleEnroll` (`internal/gateway/attestenrollnet.go`) already fail-closes on an unrecognized pre-auth
token before issuing a challenge (R34-2 part 1). Credential activation (D184) binds the AK to the EK the
device submitted, but nothing binds *that EK* to a real TPM. `internal/attest` already reconstructs an
`ecdsa.PublicKey` from a marshaled TPM2B_PUBLIC (`publicToECDSA`, used by `ParseAKPublicKey`), and the EK
is the same ECC-P256 shape — so the crypto reconstruction is reusable. The verifier runs server-side with
no TPM.

## Goals / Non-Goals

**Goals:**
- Refuse a network enrollment whose EK is not certified by a manufacturer root, when the operator has
  configured a roots pool — fail-closed, before any pending state is stored.
- Bind the EK cert to the EK actually being challenged (cert public key == submitted `ek_public`), so a
  genuine vendor cert for a different EK cannot launder an uncertified one.
- Keep it TPM-free and mockable: the logic is pure `crypto/x509` + key comparison, unit-testable without
  swtpm; the real-EK positive path is swtpm-gated.

**Non-Goals:**
- Endpoint-side EK-cert retrieval from the TPM NV index (the device already has to read it; that adapter
  is a follow-on, like other endpoint producers).
- Shipping real TPM vendor root bundles (operator-supplied via `OPENSHIELD_EK_ROOTS`).
- Any change to credential activation, the pre-auth token flow, or the frozen core.

## Decisions

1. **`ek_cert` is an additive proto field (7), not a core change.** `AttestationEnrollRequest` is an
   attestation capability message; adding a field regenerates only `corev1/attestation.pb.go`. The frozen
   core (`Dispatcher`/`State`/`Stage`/`Registry`/`Enforcer`/ledger) is untouched.

2. **`VerifyEKCert` does three checks, all required.** (a) `x509.ParseCertificate`; (b) chain to `roots`
   via `cert.Verify` with `KeyUsages: [ExtKeyUsageAny]` (EK certs do not carry serverAuth EKU) — and the
   TCG EK critical extensions Go does not model (`2.23.133.*`, the manufacturer/model SAN) are dropped
   from `UnhandledCriticalExtensions` before Verify so a legitimate vendor cert is not rejected as
   unparseable; (c) `cert.PublicKey.(*ecdsa.PublicKey).Equal(ParseEKPublicKey(ekPublic))`. A failure of
   ANY check is an error — the enrollment is refused. This mirrors go-attestation's EK-cert handling
   without adding the dependency.

3. **The binding check (c) is the anti-launder core.** Without it, an attacker with *any* real vendor EK
   cert (e.g. lifted from a discarded machine) could present it alongside a fabricated `ek_public` and
   the co-residence proof would then run against the fabricated EK. Requiring the cert's key to equal the
   submitted EK key means the certified EK IS the one credential activation binds the AK to.

4. **`RequireEKCertChain(roots)` gates it, off by default.** Same shape as `RequireEnrollTokens`: a
   deployment that has not configured manufacturer roots keeps working, but the gateway logs a loud warn
   naming the residual gap. When on, an absent or non-chaining `ek_cert` is refused before a challenge is
   built — no pending state, no information leaked to an unauthorized device beyond the refusal.

## Risks / Trade-offs

- **swtpm has no vendor EK cert.** The positive accept path is proven by issuing a synthetic manufacturer
  CA + an EK leaf over the swtpm's REAL EK public key, then enrolling — exercising the real `handleEnroll`
  with a chaining, bound cert. The refusal path is fully real without swtpm. This is a test-fixture
  reality, not a weakening of the check.
- **Real vendor EK certs are irregular** (critical TCG extensions, SAN-only subjects, RSA vs ECC). This
  increment handles the ECC-P256 EK shape the fleet uses and the known TCG critical OIDs; RSA EK support
  and a broader vendor-quirk matrix are hardening follow-ons, noted rather than silently assumed.
