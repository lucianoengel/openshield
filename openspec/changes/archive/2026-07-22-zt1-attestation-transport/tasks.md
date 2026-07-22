# Tasks

## 1. Subjects
- [x] 1.1 Add `SubjectAttestChallenge` and `SubjectAttestReport` to `internal/transport/nats/nats.go`.

## 2. Gateway responder
- [x] 2.1 `AttestationResponder` in `internal/gateway/attestsub.go`: holds `*AttestationVerifier`.
  `ServeChallenge(conn)` — request/reply on `SubjectAttestChallenge`: decode the subject, call
  `verifier.Challenge`, reply the nonce (reply empty on error). `SubscribeReports(conn)` — subscribe to
  `SubjectAttestReport`, unmarshal `AttestationReport`, `verifier.VerifyReport`; drop-and-count failures
  (`Rejected atomic.Int64`), like the risk/posture subscribers.

## 3. Endpoint client
- [x] 3.1 `posture.Attest(conn, tpm *attest.TPM, ak *attest.AK, subject string, pcrs []int)` in
  `internal/posture/attest.go`: `conn.Request(SubjectAttestChallenge, []byte(subject), timeout)` → nonce;
  `tpm.Quote(ak, nonce, pcrs)`; marshal an `AttestationReport`; publish on `SubjectAttestReport`.

## 4. Binary wiring
- [x] 4.1 In `cmd/openshield-gateway`, when a NATS conn and an `AttestationVerifier` are configured, start
  `ServeChallenge` + `SubscribeReports` (best-effort, logged; never fatal).

## 5. Tests (embedded NATS + swtpm-gated)
- [x] 5.1 End-to-end: embedded NATS; enroll a swtpm device (AK pub + golden baseline); start the
  responder; call `posture.Attest`; poll until `verifier.IsAttested(subject)` is true.
- [x] 5.2 Forged/stale rejected: publish a report with a wrong nonce → `Rejected` increments and the
  device is not attested.
- [x] 5.3 Challenge round-trip (no TPM needed for the reply): `Challenge` for an unenrolled subject over
  the wire yields an empty reply (the device cannot proceed).

## 6. Mutation guards
- [x] 6.1 Make `SubscribeReports` ignore the `VerifyReport` error (always treat as applied) → the
  forged-report test (5.2) FAILs (Rejected stays 0). Revert.
- [x] 6.2 Make `ServeChallenge` reply a fixed/empty nonce instead of the verifier's → the end-to-end
  test (5.1) FAILs (the quote answers the wrong nonce). Revert.

## 7. Record + close
- [x] 7.1 `docs/decisions.md`: new entry — attestation challenge/report transport; the report
  self-authenticates (no extra signature); challenge-reset race noted; enrollment distribution +
  endpoint loop deferred.
- [x] 7.2 `docs/architecture-roadmap.md`: note the ZT-1 transport shipped (operability gap closed).
- [x] 7.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...`;
  `go test ./internal/doccheck/`; sync the delta into `openspec/specs/device-attestation/spec.md`.
