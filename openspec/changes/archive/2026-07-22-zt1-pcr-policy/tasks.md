# Tasks

## 1. PCR read + expected-digest
- [x] 1.1 `(*TPM) ReadPCRs(pcrs []int) (map[int][]byte, error)` in `internal/attest/pcr.go`: `TPM2_PCRRead`
  the SHA-256 bank for the given indices; return index→value.
- [x] 1.2 `ExpectedPCRDigest(values map[int][]byte, selection []int) ([]byte, error)`: SHA-256 over the
  selected PCR values concatenated in ascending index order (matching the TPM's quote digest); error if
  a selected PCR is missing from values.

## 2. PCR policy
- [x] 2.1 `PCRPolicy` in `internal/attest/pcr.go`: `NewPCRPolicy(golden map[int][]byte)` (error on empty
  baseline). `Evaluate(vq *VerifiedQuote) error`: derive the quoted PCR indices from `vq.PCRSelection`,
  compute the expected digest from the golden values over those indices, compare to `vq.PCRDigest`;
  return `ErrPCRMismatch` on drift, nil on match.
- [x] 2.2 `ErrPCRMismatch` typed error (symmetric with `ErrNonceMismatch`/`ErrSignature`).

## 3. Tests (swtpm-gated)
- [x] 3.1 Digest agreement: extend a couple of writable PCRs (e.g. 16, 23) to known values; `ReadPCRs`
  → golden; `Quote`+`VerifyQuote` over those PCRs; `ExpectedPCRDigest(golden, selection)` equals
  `vq.PCRDigest`.
- [x] 3.2 Compliant: `NewPCRPolicy(golden).Evaluate(vq)` is nil for the golden-state quote.
- [x] 3.3 Drift rejected: extend one PCR further (state change); re-`Quote`+`VerifyQuote`; the SAME
  policy `.Evaluate(vq2)` returns `ErrPCRMismatch`.
- [x] 3.4 Empty baseline: `NewPCRPolicy(nil)` / empty map → error.

## 4. Mutation guards
- [x] 4.1 Make `Evaluate` return nil without comparing → the drift test (3.3) FAILs. Revert.
- [x] 4.2 Make `ExpectedPCRDigest` concatenate in map/iteration order instead of ascending index → the
  digest-agreement test (3.1) FAILs (order-dependent hash). Revert.

## 5. Record + close
- [x] 5.1 `docs/decisions.md`: new entry — PCR policy gates on the golden aggregate digest; event-log
  attribution deferred with reasoning (no go-tpm parser, go-tpm-tools barred, diagnostic-not-gating).
- [x] 5.2 `docs/architecture-roadmap.md`: mark ZT-1 increment 3 shipped.
- [x] 5.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...` succeed;
  `go test ./internal/doccheck/`; sync the delta into `openspec/specs/device-attestation/spec.md`.
