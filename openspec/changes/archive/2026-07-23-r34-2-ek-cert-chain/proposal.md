## Why

R34-2 is the attestation-vs-toy line. **Part 1 (enrollment pre-auth token) shipped** — an operator token
gates *who may enroll*. But the EK itself is still unanchored: `handleEnroll` accepts whatever
`ek_public` bytes a device submits and challenges them, and credential activation (D184) proves only that
the AK is **co-resident** with *that* EK — not that the EK belongs to a genuine, manufacturer-certified
TPM. A device with any co-resident TPM, **including a software swtpm**, that also holds a valid pre-auth
token can still enroll under its chosen subject with a fabricated EK. Real zero-trust attestation requires
anchoring the EK's identity to the TPM vendor: the EK's manufacturer-issued certificate must chain to a
configured pool of manufacturer roots, and that certificate must be bound to the exact EK being
challenged. This is R34-2 part 2 (the outstanding half), verified by Test #5.

## What Changes

- **`ek_cert` on the enroll request** (`attestation.proto`): a device submits its EK certificate (DER,
  read from the TPM NV index) alongside `ek_public`. Additive field 7; regenerated with `make proto`.
- **`attest.VerifyEKCert(ekCertDER, roots, ekPublic)`** (`internal/attest/ekcert.go`): server-side,
  no TPM required. It (a) parses the X.509 EK cert, (b) verifies it chains to the manufacturer `roots`
  pool (tolerating the TCG-specific critical extensions Go does not model, and EK-cert EKU conventions),
  and (c) confirms the cert's public key **equals** the reconstructed `ek_public` — so a valid vendor
  cert for a *different* EK cannot be presented to launder an uncertified EK. `attest.LoadEKRoots(pem)`
  builds the pool; `attest.ParseEKPublicKey` reuses the existing ECC reconstruction.
- **`EnrollmentResponder.RequireEKCertChain(roots)`** (`attestenrollnet.go`): when set, `handleEnroll`
  rejects an enrollment whose `ek_cert` is absent or fails `VerifyEKCert` **before** issuing a challenge
  or storing pending state — exactly the fail-closed shape of the pre-auth token check. Off by default
  preserves the legacy behavior; a loud warn names the gap when disabled (like the pre-auth warn).
- **`OPENSHIELD_EK_ROOTS`** (`cmd/openshield-gateway`): a PEM file of manufacturer root CAs; when set,
  the responder requires a chaining EK cert.

## Capabilities

### Modified Capabilities
- `device-attestation`: network enrollment SHALL anchor the EK to a manufacturer-root-chained EK
  certificate bound to the submitted EK public key, refusing an enrollment whose EK is uncertified.

## Impact

- `proto/openshield/v1/attestation.proto` + regenerated `internal/core/corev1/attestation.pb.go`
  (additive field, no core change — an attestation capability message, not `Dispatcher`/`Stage`/ledger).
- `internal/attest`: new `ekcert.go` (`VerifyEKCert`, `LoadEKRoots`, `ParseEKPublicKey`).
- `internal/gateway/attestenrollnet.go`: `RequireEKCertChain` + the fail-closed check in `handleEnroll`.
- `cmd/openshield-gateway`: `OPENSHIELD_EK_ROOTS` wiring.
- No new dependency (stdlib `crypto/x509` + the existing `go-tpm`).
- **Honest scope:** swtpm carries no vendor EK cert, so the positive real-EK path is proven by issuing a
  synthetic manufacturer cert over the swtpm's real EK key; the refusal path (Test #5) drives the real
  enroll handler. Production EK-cert retrieval from the NV index (endpoint side) and shipping real vendor
  root bundles are follow-ons — this increment builds and gates the server-side anchor.
