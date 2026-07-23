## Context

The FIM manifest (`fim.Manifest`, D223) is JSON on disk, loaded by `fim.LoadManifest` and trusted as-is.
The DLP signed-index (ADR-9, `classify.SignIndex`/`VerifyIndex`) already establishes the operator-signs /
node-verifies model with a domain-separated Ed25519 signature. FIM reuses that model for its baseline.

## Goals / Non-Goals

**Goals:** an operator-signed baseline the node verifies before trusting; fail-closed on tamper; the node
holds only the public key; the legacy unsigned path preserved but loudly warned.

**Non-Goals:** key rotation / multiple keys; host-identity binding; hardware keys. Single-key,
domain-separated signature is the increment.

## Decisions

1. **Domain-separated Ed25519 over the canonical manifest.** `fim.SignManifest(m, priv)` marshals the
   manifest to canonical JSON and signs `"openshield-fim-baseline\x1f" + json` — a domain tag that no
   other Ed25519 signature in the system uses, so a signature minted for the baseline can never validate
   elsewhere and vice-versa (the DLP-index discipline). The signed envelope is a small JSON struct
   `{manifest, signature}` (the manifest inline, the signature base64). `fim.VerifyManifest(signed, pub)`
   parses the envelope, verifies the signature over the domain-tagged manifest bytes, and returns the
   `*Manifest` ONLY on success — fail-closed on a malformed envelope, an empty/invalid signature, or a
   wrong key. Verification precedes any use of the manifest.

2. **Canonical bytes on both sides.** The signed bytes are the exact `json.Marshal` of the `Manifest`
   (a map with sorted keys is deterministic in Go's encoder), captured once and stored inline in the
   envelope, so verify re-signs the SAME bytes it stored — no re-marshal drift. (The envelope stores the
   manifest bytes verbatim, not a re-encoded copy.)

3. **The node never signs.** `openshield-fim-baseline` (operator tool) builds the baseline from the paths
   and signs it. The engine only VERIFIES. When `OPENSHIELD_FIM_BASELINE_PUBKEY` is set, first-run
   auto-capture is DISABLED — a node that captured and trusted its own baseline could be fed tampered
   files at capture time and would trust them; the operator must provide a signed baseline. Without the
   pubkey, D223's capture-and-plain-load stays, with a loud "unsigned baseline is tamper-vulnerable" warn.

4. **Fail-closed engine load.** With a pubkey set: a missing baseline file, a malformed/unsigned/
   wrong-key manifest → the engine logs and exits (FIM must not run trusting an unverifiable baseline).
   This is the same fail-fast-on-config posture as the DLP index and the CASB catalog.

## Risks / Trade-offs

- **JSON canonicalization.** Go's `encoding/json` sorts map keys deterministically, so a round-trip is
  stable; storing the signed bytes verbatim in the envelope removes any re-marshal risk. A future format
  change to `Manifest` must keep the signed bytes = what was signed (the envelope does).
- **Single key, no rotation.** Rotating the operator key requires re-signing baselines; multiple trusted
  keys are deferred. Acceptable for the increment (same as the DLP index today).
- **The private key is the operator's responsibility** (offline, like the DLP-index key). The node holds
  only the public key; a stolen node cannot forge a baseline.
- **The unsigned path remains** for backward compatibility and low-assurance deployments — but it is
  loudly warned, so an operator who wants tamper-evidence knows to configure the key.
