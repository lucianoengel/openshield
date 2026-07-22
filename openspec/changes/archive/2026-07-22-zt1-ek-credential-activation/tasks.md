# Tasks

## 1. EK creation
- [x] 1.1 `CreateEK()` in `internal/attest/ek.go`: `CreatePrimary` an `ECCEKTemplate` EK in the
  endorsement hierarchy; return an `EK` holding the handle, name, and public area. `EK.PublicKeyBytes()`
  marshals the EK public for the server.

## 2. Server-side challenge (pure Go, no TPM)
- [x] 2.1 `NewChallenge(ekPubBytes, akName []byte) (*Challenge, secret []byte, err)` in
  `internal/attest/credential.go`: `ImportEncapsulationKey` the EK public, generate a random secret,
  `CreateCredential(rand, key, akName, secret)` → `Challenge{CredentialBlob, EncryptedSecret}` plus the
  expected secret the caller retains.
- [x] 2.2 `VerifyActivation(expected, recovered []byte) bool`: constant-time equality.

## 3. Endpoint-side activation
- [x] 3.1 `AK.Name()` accessor (the AK's TPM name, needed to bind the challenge).
- [x] 3.2 `(*TPM) Activate(ek *EK, ak *AK, c *Challenge) ([]byte, error)`: run `TPM2_ActivateCredential`
  with the AK as ActivateHandle and the EK as KeyHandle, using an EK policy session
  (`PolicySecret(endorsement)`); return the recovered secret. Flush the policy session.

## 4. Tests (swtpm-gated)
- [x] 4.1 Same-TPM round trip: create EK+AK on one swtpm; server builds a challenge for (EK pub, AK
  name); endpoint activates; recovered secret == issued secret; `VerifyActivation` true.
- [x] 4.2 Different-TPM rejection: build the challenge for TPM-A's EK but activate on TPM-B (a second
  swtpm with its own EK/AK) → activation fails OR recovers a different secret; `VerifyActivation` false.
- [x] 4.3 Substituted-AK rejection: build the challenge for AK1's name, activate with AK2 → activation
  fails (name binding broken).

## 5. Mutation guards
- [x] 5.1 Make `VerifyActivation` always return true → the direct `TestVerifyActivationRejectsMismatch`
  FAILs (the TPM already rejects a wrong EK/name, so this is the check's own negative test). Revert.
- [x] 5.2 Build the challenge with a fixed/empty AK name instead of the real one → the round-trip (4.1)
  FAILs to activate. Revert.

## 6. Record + close
- [x] 6.1 `docs/decisions.md`: new entry — EK credential activation binds AK↔genuine TPM via go-tpm's
  `CreateCredential` (still no go-tpm-tools); EK-cert-chain validation scoped as the production step.
- [x] 6.2 `docs/architecture-roadmap.md`: mark ZT-1 increment 2 shipped.
- [x] 6.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...` succeed;
  `go test ./internal/doccheck/`; sync the delta into `openspec/specs/device-attestation/spec.md`.
