# Tasks

## 1. Test harness (swtpm, gated)
- [x] 1.1 Add `internal/attest/swtpm_test.go`: `requireSWTPM(t)` skips when the `swtpm` binary is absent
  (mirror `requireDB`); `startSWTPM(t)` spawns `swtpm socket --tpm2 --server type=tcp,port=… --ctrl
  type=tcp,port=… --tpmstate dir=<t.TempDir()> --flags not-need-init`, waits for the socket, returns
  its `host:port`, and registers cleanup that kills the process.
- [x] 1.2 `openTPM(addr)` in `internal/attest/tpm.go`: when `addr`/`OPENSHIELD_TPM_ADDR` is set, dial
  TCP and wrap with `transport.FromReadWriter`; else open `/dev/tpmrm0`. Run `TPM2_Startup(CLEAR)` on a
  freshly-started swtpm. Sanity test: connect to a spawned swtpm and startup succeeds.

## 2. AK creation
- [x] 2.1 `CreateAK(tpm)` in `internal/attest/ak.go`: `CreatePrimary` an EK-like primary in the
  endorsement hierarchy, then create a restricted ECDSA-P256/SHA-256 signing child
  (`SignEncrypt|Restricted|FixedTPM|FixedParent|SensitiveDataOrigin|UserWithAuth`). Return an `AK`
  holding the loaded handle and the public key.
- [x] 2.2 `AK.PublicKeyBytes()` / `ParseAKPublicKey(b)`: marshal the AK public half and parse it back to
  a `crypto/ecdsa.PublicKey`. Test: round-trip yields an equal key; the marshaled blob contains no
  private material.

## 3. Quote generation
- [x] 3.1 `NewNonce()` → 32 crypto-random bytes.
- [x] 3.2 `(*AK) Quote(tpm, nonce, pcrs []int)`: `TPM2_Quote` with `QualifyingData=nonce`,
  `PCRSelect=<sha256, pcrs>`, AK scheme. Return `Quote{Attest []byte, Signature []byte, PCRSelection}`.
  Test (swtpm): quote PCRs [0,7]; assert the parsed attest is a quote struct whose extraData==nonce and
  whose PCR selection matches.

## 4. Server-side verification
- [x] 4.1 `VerifyQuote(akPub, nonce, q Quote) (VerifiedQuote, error)` in `internal/attest/verify.go`:
  parse `TPMS_ATTEST`; require magic==TPM_GENERATED and type==ATTEST_QUOTE; require `extraData==nonce`
  (typed `ErrNonceMismatch`); verify ECDSA signature (SHA-256 over the marshaled attest) against
  `akPub`. Return `VerifiedQuote{PCRDigest, PCRSelection}`.
- [x] 4.2 Tests (swtpm round-trip): valid quote verifies and returns the PCR digest; wrong-nonce →
  `ErrNonceMismatch`; flipped signature byte → error; verify against a second AK's public key → error.

## 5. Mutation guards
- [x] 5.1 Comment out the `extraData==nonce` check → the wrong-nonce/replay test FAILs. Revert.
- [x] 5.2 Make the signature check always return nil → the tampered-signature AND wrong-AK tests FAIL.
  Revert.

## 6. CI + build
- [x] 6.1 Add `swtpm` install (`apt-get install -y swtpm`) to the Linux CI job so the attest tests run
  in CI (skipped on macOS/Windows via `requireSWTPM`).
- [x] 6.2 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows go build ./...` and `GOOS=darwin
  go build ./...` succeed (attest package compiles cross-platform; TPM device open guarded per-GOOS).

## 7. Record + close
- [x] 7.1 `docs/decisions.md`: new entry — go-tpm over go-tpm-tools (supply-chain), swtpm-gated tests,
  raw-AK-trust scope caveat (EK binding is increment 2).
- [x] 7.2 `docs/architecture-roadmap.md`: mark ZT-1 increment 1 (attestation core) shipped.
- [x] 7.3 `go test ./internal/doccheck/`; sync the delta into `openspec/specs/device-attestation/spec.md`.
