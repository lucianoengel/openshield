## 1. Proto
- [x] 1.1 Add `bytes ek_cert = 7;` to `AttestationEnrollRequest` (attestation.proto) with a doc comment; `make proto`; stage the regenerated pb.go.

## 2. attest: EK-cert verification
- [x] 2.1 `ParseEKPublicKey(b []byte) (*ecdsa.PublicKey, error)` — reuse `publicToECDSA` (exported seam for the EK, same ECC-P256 shape as the AK).
- [x] 2.2 `LoadEKRoots(pem []byte) (*x509.CertPool, error)` — build a manufacturer-roots pool; empty/malformed PEM is an error.
- [x] 2.3 `VerifyEKCert(ekCertDER []byte, roots *x509.CertPool, ekPublic []byte) error` — parse cert; drop TCG critical OIDs from UnhandledCriticalExtensions; `cert.Verify` (Roots, KeyUsages=[Any]); confirm cert pubkey `.Equal` the reconstructed EK pubkey. Any failure → error.

## 3. gateway: gate the enroll path
- [x] 3.1 `EnrollmentResponder` gains `ekRoots *x509.CertPool` + `requireEKCert bool`; `RequireEKCertChain(roots)` toggle (fail-closed with a nil pool: enforcement on, every enroll refused — the safe misconfig).
- [x] 3.2 In `handleEnroll`, after the token check: if `requireEKCert`, call `VerifyEKCert(req.GetEkCert(), ekRoots, req.GetEkPublic())`; on error return "EK not manufacturer-attested" BEFORE building a challenge or storing pending state.

## 4. cmd wiring
- [x] 4.1 `cmd/openshield-gateway`: `OPENSHIELD_EK_ROOTS` PEM file → `LoadEKRoots` → `RequireEKCertChain`; loud warn when unset (mirrors the pre-auth warn).

## 5. Tests (mutation-verified)
- [x] 5.1 `VerifyEKCert` unit (no swtpm): synthetic manufacturer CA + EK leaf over a known key → nil; wrong roots → error; cert-for-a-different-key (binding) → error; absent cert → error.
- [x] 5.2 Real enroll path — refusal (Test #5): `handleEnroll` with `RequireEKCertChain` on and no/bad `ek_cert` → refused, no pending state.
- [x] 5.3 Real enroll path — accept (swtpm-gated): swtpm EK + synthetic manufacturer cert over its REAL EK key → `handleEnroll` issues a challenge (not refused).
- [x] 5.4 Mutations: skip the chain check → the wrong-roots test FAILs; skip the pubkey-binding check → the different-key test FAILs; `handleEnroll` skips VerifyEKCert → the refusal test FAILs.

## 6. Gate + close
- [ ] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; proto-check clean; cross-compile; restore binaries.
- [ ] 6.2 decisions.md (D218); sync device-attestation spec; doccheck.
- [ ] 6.3 Archive; commit; push; roadmap (R34-2 fully done).
