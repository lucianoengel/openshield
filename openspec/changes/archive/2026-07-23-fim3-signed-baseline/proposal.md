## Why

FIM (D223/D228) detects tampering of critical files against a known-good baseline — but the baseline
manifest is a **plain, unsigned file**. An attacker who can write it can rewrite the recorded hashes to
match their tampered files, and FIM sees no drift. An integrity monitor whose own baseline is silently
rewritable is only as strong as the file permissions on the manifest. This increment makes the baseline
**tamper-evident**: an operator signs it offline with their private key, the node verifies the signature
against a trusted operator public key before trusting it, and a manifest that does not verify is refused.
A node that could mint its own trusted baseline would defeat the point, so when verification is required
the baseline MUST be operator-signed — the node never holds the signing key (the DLP signed-index model,
ADR-9/D100).

## What Changes

- **Sign/verify the baseline** — `fim.SignManifest` (operator side) and `fim.VerifyManifest` /
  `fim.LoadSignedManifest` (node side): a domain-separated Ed25519 signature over the canonical manifest,
  fail-closed on a malformed envelope, a missing/invalid signature, or the wrong key. Verification
  happens BEFORE the manifest is trusted.
- **A signing tool** — `cmd/openshield-fim-baseline` (`keygen` + `build`): the operator captures a
  baseline from the critical paths and signs it with their key, producing the exact bytes the engine
  verifies. The node is configured with only the operator PUBLIC key.
- **Engine verification** — when `OPENSHIELD_FIM_BASELINE_PUBKEY` is set, the engine loads the baseline
  via `LoadSignedManifest` (a valid operator signature required; a bad/unsigned baseline is fatal, and
  first-run auto-capture is disabled — the node must not self-sign its own trusted baseline). Without the
  pubkey, the legacy plain load (D223) is preserved but **loudly warned** as tamper-vulnerable
  (opt-in-closed per deployment, exactly like the DLP index).

## Capabilities

### New Capabilities
<!-- none — extends the file-integrity-monitoring capability. -->

### Modified Capabilities
- `file-integrity-monitoring`: the baseline MAY be operator-signed and, when a trusted operator key is
  configured, MUST verify against it before it is trusted — so an attacker who can write the baseline
  file cannot hide drift by rewriting it.

## Impact

- **Code:** new `internal/fim/signed.go` (sign/verify/load); new `cmd/openshield-fim-baseline` (keygen +
  build+sign); `cmd/openshield-engine/main.go` (verify when a pubkey is set). No proto, no migration, no
  new dependency (`crypto/ed25519` + the existing manifest JSON).
- **Testing:** sign→verify round-trip; a tampered manifest fails; a wrong key fails; an unsigned manifest
  is refused when a pubkey is required; the engine load path (signed accepted, tampered rejected). No
  root.
- **Deferred:** key rotation / multiple trusted keys; binding the baseline to a host identity; a
  hardware-backed key. The domain-separated single-key signature is the increment.
