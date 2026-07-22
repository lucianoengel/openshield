## Why

Device posture is self-reported booleans. A compromised-but-alive agent signs `Compliant=true` and the
gateway believes it — the posture signature (SEC-12) proves *which agent* said it, not that the claim
is *true*. ZT-1 hardens this with a hardware root of trust: a TPM-signed quote over the machine's
measured-boot state, which a compromised OS cannot forge. This first increment builds the attestation
CORE — generating and verifying a nonce-fresh TPM quote — so later increments can bind it to enrollment
(EK→AK), apply a measured-boot policy, and feed an `attested` posture signal.

## What Changes

- A new `internal/attest` package: create a TPM Attestation Key (AK), produce a `TPM2_Quote` over a
  selected PCR set with a server-supplied **nonce** as qualifying data, and **verify** that quote
  server-side against the AK's public key — checking the signature AND that the quote's nonce matches
  the one the verifier issued (freshness — a captured old quote is rejected).
- **Dependency decision:** built on `go-tpm` (already an indirect dependency), *not* `go-tpm-tools`,
  whose current versions drag in a heavy supply-chain tree (Intel TDX, AMD SEV-SNP, GCP
  confidential-space) a minimal security tool should not absorb for a TPM feature.
- **Test harness:** a `swtpm` (software TPM 2.0) subprocess over a TCP socket, connected via
  `go-tpm/transport` — no cgo, no new Go dependency. The attest tests are **gated** (skip when `swtpm`
  is absent, like the Postgres integration tests); a CI job installs `swtpm` so they run in CI.

## Capabilities

### New Capabilities
- `device-attestation`: generate a TPM-signed quote over the machine's PCR state bound to a
  server-issued nonce, and verify it server-side against the attesting key — the hardware-root-of-trust
  primitive posture attestation is built on.

### Modified Capabilities
<!-- none in this increment -->

## Impact

- **Code:** a new `internal/attest` package (TPM key/quote via `go-tpm`; a swtpm-gated test harness) and
  a CI job that installs `swtpm`.
- **No proto/core change** in this increment (posture/enrollment wiring is increments 2–4). No new Go
  dependency — `go-tpm` is already vendored; `swtpm` is a system binary used only by tests.
- **Scope:** this is increment 1 of 4 for ZT-1 (core → EK/AK credential activation → measured-boot
  event-log/PCR policy → posture wiring). Each lands and is tested independently.
