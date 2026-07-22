# Tasks

## 1. Proto
- [x] 1.1 Add to `proto/openshield/v1/attestation.proto`: `AttestationEnrollRequest{subject, bytes
  ek_public, bytes ak_public, bytes ak_name, map<uint32,bytes> golden}`, `AttestationEnrollChallenge{bytes
  credential_blob, bytes encrypted_secret, string error}`, `AttestationActivation{subject, bytes secret}`,
  `AttestationEnrollResult{bool enrolled, string error}`. `make proto`; commit generated `corev1`.

## 2. Subjects
- [x] 2.1 Add `SubjectAttestEnroll` and `SubjectAttestActivate` to `internal/transport/nats/nats.go`.

## 3. Gateway enrollment responder
- [x] 3.1 `EnrollmentResponder` in `internal/gateway/attestenrollnet.go`: holds `*AttestationVerifier` +
  a pending map (subject → {akPublic, golden, expectedSecret}). `ServeEnroll(conn)` — request/reply on
  `SubjectAttestEnroll`: parse the request, `attest.NewChallenge(ek_public, ak_name)`, store pending, reply
  the challenge (reply `error` set on any failure, no pending stored). `ServeActivate(conn)` — request/reply
  on `SubjectAttestActivate`: look up pending, `attest.VerifyActivation`, on success `ParseAKPublicKey` +
  `verifier.Enroll` and clear pending, reply `enrolled=true`; any failure replies `enrolled=false` and does
  not enroll.

## 4. Endpoint client
- [x] 4.1 `posture.Enroll(conn, tpm *attest.TPM, ek *attest.EK, ak *attest.AK, subject string, pcrs []int)
  error` in `internal/posture/enrollnet.go`: build the request (`ek/ak.PublicKeyBytes()`, `ak.Name()`,
  `tpm.ReadPCRs`), request the challenge (fail on `error`), `tpm.Activate(ek, ak, challenge)`, request the
  activation, fail unless `enrolled`.

## 5. Binary wiring
- [x] 5.1 In `cmd/openshield-gateway`, when `OPENSHIELD_ATTEST` is set, also start the `EnrollmentResponder`
  (`ServeEnroll` + `ServeActivate`) so devices can self-enroll over the wire.

## 6. Tests (embedded NATS + swtpm-gated)
- [x] 6.1 End-to-end: a swtpm device runs `posture.Enroll` (create EK+AK); the gateway enrolls it; the
  device then attests (`posture.Attest`) and `IsAttested` is true — enrollment + attestation over the wire,
  no file.
- [x] 6.2 Fake device refused: present a device whose AK is on a DIFFERENT TPM than the EK (cannot
  activate) → `posture.Enroll` returns an error and the subject is not enrolled (`Challenge` →
  `ErrNotEnrolled`).
- [x] 6.3 Activation without a pending enroll: `ServeActivate` for a subject with no pending record replies
  `enrolled=false`, does not enroll.

## 7. Mutation guards
- [x] 7.1 Make `ServeActivate` skip `VerifyActivation` (enroll regardless) → the fake-device test (6.2)
  FAILs (a device that couldn't activate gets enrolled). Revert.
- [x] 7.2 Make `ServeActivate` reply `enrolled=true` without calling `verifier.Enroll` → the end-to-end
  test (6.1) FAILs (the device is not actually enrolled, so it cannot attest). Revert.

## 8. Record + close
- [x] 8.1 `docs/decisions.md`: new entry (D191) — automated network enrollment via credential activation;
  AK-genuine proven over the wire; TOFU golden baseline (honest); EK-cert + enrollment-authz follow-ups.
- [x] 8.2 `docs/architecture-roadmap.md`: mark automated network enrollment shipped — ZT-1 operability
  complete.
- [x] 8.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` + `make proto-check` green; `GOOS=windows/darwin go
  build ./...`; `go test ./internal/doccheck/`; sync the delta into
  `openspec/specs/device-attestation/spec.md`.
