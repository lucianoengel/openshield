## Context

Posture today is a set of self-reported booleans signed by the agent's software key (SEC-12). The
signature authenticates *the agent*, not *the machine state* — a rootkit that keeps the agent process
alive can sign `Compliant=true` forever. A TPM changes the trust root: the machine's boot measurements
are extended into PCRs by firmware/bootloader before the OS is in a position to lie, and the TPM signs
a **quote** over those PCRs with a key whose private half never leaves the chip. This increment builds
the quote generate/verify primitive; binding the key to a genuine TPM (EK cert) and turning PCR values
into a posture verdict come in later increments.

## Goals / Non-Goals

**Goals**
- Create a restricted signing **Attestation Key (AK)** in the TPM and export its public half.
- Produce a `TPM2_Quote` over a selected PCR set, bound to a caller-supplied **nonce**.
- Verify that quote server-side: signature valid under the AK public key **and** the quote's
  qualifying data equals the nonce the verifier issued (anti-replay), exposing the attested PCR digest.
- Prove it against a real (software) TPM in tests, with zero new Go dependencies.

**Non-Goals (later increments)**
- EK certificate → AK credential-activation binding (increment 2) — this increment's AK is trusted by
  raw public key, not yet proven to live in a specific genuine TPM.
- Measured-boot event-log parsing and PCR policy (increment 3).
- Proto/posture/core wiring and the `attested` signal (increment 4).
- Windows/macOS TPM access (Linux `/dev/tpmrm0` + swtpm only here).

## Decisions

### D1 — `go-tpm`, not `go-tpm-tools`
Build directly on `github.com/google/go-tpm` (already an indirect dependency at v0.9.8; its `tpm2`
package exposes the typed `CreatePrimary`, `Create`/`CreateLoaded`, `Quote`, `PCRRead`, `ReadPublic`
commands and a `transport` abstraction). We deliberately do **not** adopt
`github.com/google/go-tpm-tools`: its current releases pull Intel `go-tdx-guest`, AMD `go-sev-guest`,
and `GoogleCloudPlatform/confidential-space` — a large confidential-computing tree irrelevant to a TPM
quote and at odds with this project's minimal, auditable dependency posture. The cost is that we write
the AK template and quote-verify logic ourselves; that code is small and security-critical enough to
want in-tree and reviewable anyway. Recorded as a decisions.md entry.

### D2 — swtpm subprocess as the test substrate, gated like Postgres
Tests spawn `swtpm socket --tpm2` on a TCP port (`--tpmstate` in a `t.TempDir()`, `--flags
not-need-init`), then connect with `transport.FromReadWriter(net.Dial("tcp", …))` and run
`TPM2_Startup(CLEAR)`. No cgo, no new Go module. A `requireSWTPM(t)` helper skips the test when the
`swtpm` binary is absent, exactly mirroring `requireDB(t)` — so the suite is green on a machine without
a TPM, and a CI job installs `swtpm` (`apt-get install -y swtpm`) so the attest tests actually execute
in CI. Runtime code selects the transport from `OPENSHIELD_TPM_ADDR` (a `host:port` swtpm socket for
dev/test) else the Linux resource-manager device `/dev/tpmrm0`.

### D3 — AK shape: restricted ECDSA-P256 signing key in the endorsement hierarchy
The AK is created under a primary in the endorsement hierarchy (`TPMRHEndorsement`) with a standard
EK-like primary template, then a child **restricted signing** key (`SignEncrypt | Restricted |
FixedTPM | FixedParent | SensitiveDataOrigin | UserWithAuth`), ECDSA over P-256 with SHA-256. Restricted
+ FixedTPM is what makes the key meaningful: the TPM will only sign TPM-internal structures (like a
quote) with it, and the private key cannot be exported. The AK public half is marshaled (the TPM
`TPM2BPublic`, plus a convenience `crypto/ecdsa.PublicKey`) so a server can persist it and verify later
quotes. RSA support is deferred; P-256 keeps the verify path on `crypto/ecdsa`.

### D4 — Verification is pure Go, no TPM needed
`VerifyQuote` runs on the *server*, which has no TPM. It (a) parses the `TPMS_ATTEST` blob, (b) confirms
`attest.Magic == TPM_GENERATED_VALUE` and `attest.Type == TPM_ST_ATTEST_QUOTE` (reject anything that
isn't a genuine quote structure), (c) checks `attest.ExtraData == nonce` — the anti-replay gate — (d)
recomputes the signing digest (SHA-256 over the marshaled attest blob) and verifies the ECDSA signature
against the stored AK public key, and (e) returns the attested PCR digest (`quote.PCRDigest`) and PCR
selection for a future policy layer. Every check is a hard failure that returns a typed error; there is
no "warn and continue".

### D5 — The nonce is the whole anti-replay story (this increment)
The verifier is responsible for issuing a fresh, unpredictable nonce per attestation and remembering it
until the quote returns; `VerifyQuote` only enforces "this quote's extraData equals the nonce you gave
me". A captured quote carries an old nonce and fails. Nonce *issuance/expiry* state lives with the
caller (posture verifier, increment 4); here we ship a `NewNonce()` helper (32 random bytes) and the
equality check, and test replay by verifying a quote-for-nonce-A against expected-nonce-B.

## Risks / Trade-offs

- **swtpm not in CI by default** → mitigated by adding it to a CI job; the gate means its absence
  degrades to skip, never to a false green (the local `make all` runs them for real here).
- **Raw-AK trust** → an attacker who can run code on the endpoint can create their *own* AK and quote
  their *own* faked PCRs; without EK binding (increment 2) the server can't tell that AK from a genuine
  TPM's. This increment is explicitly the crypto core, not the trust binding — the proposal and the
  decisions entry state this so the property isn't over-claimed.
- **go-tpm API churn** → pinned at v0.9.8 (already in `go.sum`); the typed command API is stable across
  0.9.x.

## Migration Plan

Additive only: a new `internal/attest` package and a CI step. No schema, proto, DB, or existing-package
changes. Nothing to roll back beyond deleting the package.

## Open Questions

- Whether to standardize on ECDSA-P256 or also support RSA-2048 AKs for TPMs that restrict ECC — deferred
  to increment 2 when we meet real EK certs. P-256 is universal on TPM 2.0 and sufficient here.
