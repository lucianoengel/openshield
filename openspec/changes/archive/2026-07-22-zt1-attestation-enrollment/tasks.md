# Tasks

## 1. Enrollment record + serialization
- [x] 1.1 `AttestationEnrollment` in `internal/attest/enrollment.go`: `{Subject string; AKPublic []byte;
  Golden map[int][]byte}`. JSON (de)serialization with `ak_public` base64 and `pcrs` index→hex
  (`MarshalEnrollments`/`ParseEnrollments` over `{"enrollments":[...]}`), and a `Validate()` that rejects
  an empty subject / unparseable AK (`ParseAKPublicKey`) / empty baseline.

## 2. Endpoint capture
- [x] 2.1 `posture.BuildEnrollment(tpm *attest.TPM, ak *attest.AK, subject string, pcrs []int)
  (attest.AttestationEnrollment, error)`: marshal `ak.PublicKeyBytes()`, `tpm.ReadPCRs(pcrs)` for the
  golden baseline, return the record.

## 3. Gateway loader
- [x] 3.1 `gateway.LoadAttestationEnrollments(v *AttestationVerifier, path string) (int, error)` in
  `internal/gateway/attestenroll.go`: read the file, `ParseEnrollments`, and for each record parse the AK
  (`attest.ParseAKPublicKey`) and `v.Enroll(subject, akPub, golden)`; a bad record fails the whole load
  (never a silent skip). Return the count enrolled.

## 4. Binary wiring
- [x] 4.1 In `cmd/openshield-gateway`, when `OPENSHIELD_ATTEST_ENROLLMENTS` is set, load enrollments into
  the verifier before starting the responder; log the count (replacing the empty-verifier warning).

## 5. Tests (swtpm-gated where a TPM is needed)
- [x] 5.1 Round-trip: a swtpm device → `BuildEnrollment` → `MarshalEnrollments` to a temp file →
  `LoadAttestationEnrollments` into a fresh verifier → the full challenge/quote/`VerifyReport` succeeds
  (`IsAttested` true) — a distributed enrollment is functionally identical to a programmatic one.
- [x] 5.2 Malformed record fails the load (no TPM): empty subject, bad AK bytes, and empty baseline each
  return an error from `LoadAttestationEnrollments`, and the verifier is not partially enrolled.
- [x] 5.3 JSON (de)serialization is stable (no TPM): `ParseEnrollments(MarshalEnrollments(x))` == x.

## 6. Mutation guards
- [x] 6.1 Make `LoadAttestationEnrollments` skip a record whose `Validate` fails (continue instead of
  returning the error) → the malformed-record test (5.2) FAILs. Revert.
- [x] 6.2 Make `LoadAttestationEnrollments` not call `v.Enroll` (load but don't enroll) → the round-trip
  test (5.1) FAILs (`IsAttested` false). Revert.

## 7. Record + close
- [x] 7.1 `docs/decisions.md`: new entry (D189) — file-based enrollment distribution (posture-roster
  model); fail-closed on bad records; automated network enrollment with live activation is the follow-up.
- [x] 7.2 `docs/architecture-roadmap.md`: note enrollment distribution shipped (only the re-attestation
  loop + automated network enrollment remain for ZT-1 operability).
- [x] 7.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...`;
  `go test ./internal/doccheck/`; sync the delta into `openspec/specs/device-attestation/spec.md`.
