# Tasks

## 1. Endpoint loop
- [x] 1.1 `posture.AttestLoop(ctx, conn, tpm *attest.TPM, ak *attest.AK, subject string, pcrs []int,
  interval time.Duration, log *slog.Logger)` in `internal/posture/attestloop.go`: attest once
  immediately, then re-attest each tick via `retain.Loop`; log a failed attempt (best-effort, never
  fatal); return on context cancellation.

## 2. Fleet-agent wiring
- [x] 2.1 In `cmd/openshield-fleet-agent`, when attestation is configured (a TPM address + a PCR set,
  e.g. `OPENSHIELD_TPM_ADDR` + `OPENSHIELD_ATTEST_PCRS`), open the TPM, create/load the AK, and start
  `AttestLoop` in a goroutine (best-effort; a TPM-open failure logs and skips, never aborts the agent).

## 3. Tests (embedded NATS + swtpm-gated)
- [x] 3.1 Good device stays attested: enroll a device, start the responder, run `AttestLoop` at a short
  interval; poll until `IsAttested` is true and confirm it remains true across a couple of cycles.
- [x] 3.2 Drift loses attestation (continuous verification): with the loop running and the device
  attested, extend a PCR (drift); poll until the responder's `Rejected` counter rises (a re-attestation
  was rejected) and `IsAttested` is false — proving the loop re-checks, not attests-once.
- [x] 3.3 Non-positive interval / cancellation: `AttestLoop` with a cancelled context returns promptly
  (reuses the `retain.Loop` guard).

## 4. Mutation guards
- [x] 4.1 Make `AttestLoop` attest once and NOT loop (skip `retain.Loop`) → the drift test (3.2) FAILs
  (drift is never re-detected; `Rejected` stays 0). Revert.
- [x] 4.2 Make the loop's attempt a no-op (never call `Attest`) → the good-device test (3.1) FAILs
  (never reaches attested). Revert.

## 5. Record + close
- [x] 5.1 `docs/decisions.md`: new entry (D190) — continuous re-attestation loop; drift drops attestation
  within a cycle; errors non-fatal; automated network enrollment remains the last ZT-1 follow-up.
- [x] 5.2 `docs/architecture-roadmap.md`: note the re-attestation loop shipped (ZT-1 live loop complete).
- [x] 5.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...`;
  `go test ./internal/doccheck/`; sync the delta into `openspec/specs/device-attestation/spec.md`.
