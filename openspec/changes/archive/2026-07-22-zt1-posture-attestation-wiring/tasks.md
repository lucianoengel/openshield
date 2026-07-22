# Tasks

## 1. Contract + proto
- [x] 1.1 `core.DevicePosture.Attested bool` in `internal/core/pipeline.go` (doc: server-verified, never
  self-reported).
- [x] 1.2 `policy.buildInput` exposes `device_posture.attested` in `internal/policy/mapping.go`.
- [x] 1.3 New `AttestationReport` message in `proto/openshield/v1/attestation.proto` (subject, bytes
  nonce, bytes quote_attest, bytes quote_sig_r, bytes quote_sig_s — no self-asserted `attested`).
  `make proto`; commit generated `corev1`.

## 2. Attestation verifier (gateway)
- [x] 2.1 `AttestationVerifier` in `internal/gateway/attestation.go`: `Enroll(subject, akPub
  *ecdsa.PublicKey, golden map[int][]byte)` (stores per subject; needs a non-empty baseline);
  `Challenge(subject) ([]byte, error)` mints a fresh one-shot nonce (attest.NewNonce), stores it (error
  if subject not enrolled).
- [x] 2.2 `VerifyReport(report *corev1.AttestationReport) error`: require the report's nonce == the
  stored issued nonce (then consume it), `attest.VerifyQuote(enrolledAK, nonce, quote)`,
  `attest.PCRPolicy(golden).Evaluate(vq)`; on full success mark the subject attested. Typed errors for
  unenrolled / stale-nonce / bad-quote / drift. `IsAttested(subject) bool`.

## 3. Access-proxy wiring
- [x] 3.1 `AccessProxy.SetAttestationVerifier(v)`; in the access handler overlay
  `dp.Attested = v.IsAttested(deviceSubject)` (and `HasPosture=true` when attested) onto the posture the
  policy sees — server truth, independent of self-report.

## 4. Tests
- [x] 4.1 End-to-end (swtpm): create EK/AK, enroll (AK pub + golden baseline captured via ReadPCRs),
  `Challenge` → nonce, endpoint quotes over the nonce → build `AttestationReport`, `VerifyReport` → nil,
  `IsAttested` true.
- [x] 4.2 Replay rejected: submit the same report twice → the second fails (nonce consumed).
- [x] 4.3 Drift not attested: after enrollment+challenge, extend a PCR (drift), quote, `VerifyReport` →
  `ErrPCRMismatch`, `IsAttested` false.
- [x] 4.4 Unenrolled rejected: `Challenge`/`VerifyReport` for an unknown subject → error.
- [x] 4.5 Policy integration (no TPM): a rego requiring `device_posture.attested` ALLOWs an attested
  DevicePosture and DENYs an unattested one, through the real dispatcher (peer_test.go shape).
- [x] 4.6 Access-proxy overlay (no TPM): with a verifier reporting attested for the device subject, the
  DevicePosture the policy sees has `Attested=true`; without, false.

## 5. Mutation guards
- [x] 5.1 Make `VerifyReport` skip the nonce-consume/match → the replay test (4.2) FAILs. Revert.
- [x] 5.2 Make `VerifyReport` mark attested before the PCR-policy check → the drift test (4.3) FAILs.
  Revert.
- [x] 5.3 Make the access overlay ignore the verifier (leave Attested false) → test 4.6 FAILs. Revert.

## 6. Record + close
- [x] 6.1 `docs/decisions.md`: new entry — attested is gateway-verified (nonce+quote+PCR), never
  self-reported; NATS challenge/report transport deferred (primitive-then-transport, cf. D89→D91).
- [x] 6.2 `docs/architecture-roadmap.md`: mark ZT-1 increment 4 shipped — ZT-1 COMPLETE.
- [x] 6.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` + `make proto-check` green; `GOOS=windows/darwin go
  build ./...`; `go test ./internal/doccheck/`; sync deltas into
  `openspec/specs/device-attestation/spec.md`.
