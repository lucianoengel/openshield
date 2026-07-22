## Context

A TPM quote's `TPMS_QUOTE_INFO` carries a `PCRDigest`: the hash, under the signing key's name
algorithm (SHA-256 for our AK), over the concatenation of the selected PCRs' values in ascending index
order. Increment 1's `VerifyQuote` already extracts this digest and the PCR selection. Attestation
verification then reduces to: does this digest equal the digest of the state we expect? The "state we
expect" is a set of golden per-PCR values captured from a known-good machine.

## Goals / Non-Goals

**Goals**
- `ReadPCRs(pcrs)` — read current SHA-256-bank PCR values from a TPM (capture a golden baseline).
- `ExpectedPCRDigest(values, selection)` — recompute the TPM's aggregate digest in pure Go.
- `PCRPolicy` — from golden values, evaluate a `VerifiedQuote`: match → compliant, drift → typed error.

**Non-Goals**
- Event-log (`binary_bios_measurements`) parsing / per-measurement attribution — deferred (see below).
- Posture wiring, proto fields (increment 4).
- Configurable multi-baseline / allow-lists of acceptable states — a single golden baseline here; a set
  is a trivial later extension.

## Decisions

### D1 — Gate on the aggregate PCR digest, computed to match the TPM exactly
The quote commits to `H(PCR[i1] || PCR[i2] || … )` for the selected, ascending PCR indices. `PCRPolicy`
recomputes that hash from the golden values over the quote's own reported selection and compares it —
constant work, no TPM, and it is the exact value the TPM signed, so a match means the machine's measured
state is bit-identical to golden. Ascending-index ordering and the SHA-256 bank are fixed to match the
AK name algorithm and the quote's selection.

### D2 — Golden baseline is captured, not assumed
`ReadPCRs` reads the live PCR values so an operator captures a baseline from a machine they trust; the
policy stores those values. This keeps the trust decision explicit and operator-owned (which state is
"good" is a deployment choice), consistent with the project's "no hidden defaults" stance — an empty
baseline is an error, never an implicit allow.

### D3 — Event-log attribution is deferred, and the deferral is stated
The measured-boot event log would let a verifier explain *which* component changed and replay events to
derive expected PCRs from a manifest rather than raw golden values. It is genuinely useful but: (a)
go-tpm has no TCG event-log parser; (b) go-tpm-tools has one but is barred by D183's supply-chain
decision; (c) the TCG PC-Client event-log binary format (crypto-agile `TCG_PCR_EVENT2` records) is a
substantial, error-prone hand-roll. Crucially it changes nothing about the allow/deny — the digest
comparison is the gate; attribution is diagnostics. So it is deferred with this reasoning recorded,
not silently dropped.

### D4 — Reject is a typed error, symmetric with the rest of `internal/attest`
`ErrPCRMismatch` mirrors `ErrNonceMismatch`/`ErrSignature`: a caller distinguishes "attestation valid
but state is wrong" from "attestation itself failed", which matter differently to a posture policy
(increment 4).

## Risks / Trade-offs

- **A single golden baseline is brittle across a heterogeneous fleet** — different hardware/firmware
  yields different PCRs. Accepted for this increment; a set-of-baselines (any-match) is a small follow-on
  and noted.
- **Golden capture trusts the capturing machine** — inherent to measured boot; the operator owns that
  trust decision (D2).

## Migration Plan

Additive to `internal/attest`; no schema/proto/core change.

## Open Questions

- Whether to accept a *set* of golden baselines (fleet heterogeneity) now or in increment 4 when posture
  policy consumes this. Deferring; single baseline is sufficient to prove the gate.
