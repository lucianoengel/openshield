## Context

The worker loads three serialized DLP indexes (`EDMIndex`, `RecordIndex`, `DocumentIndex`, each with a
`Marshal()`/`Load*` pair) from operator-pointed files, unsigned. The signed custom-rules path (D100)
already establishes the exact trust model to mirror: an operator signs data with an operator key, the
node loads it ONLY after verifying against a trusted operator public key, and a compromised control
plane can DISTRIBUTE but cannot FORGE (T2/D14). This ticket applies that model to the index data.

## Goals / Non-Goals

**Goals:**
- Close the ADR-9 gap: an index shipped into the sandbox can be cryptographically bound to the operator.
- Fail-closed verification: a missing/tampered/wrong-key/wrong-kind index loads NOTHING.
- An operator tool to build + sign the three index kinds from plain input.
- Preserve the k-anonymized boundary — signing wraps the already-hash-only `Marshal()` bytes; no raw
  data enters the envelope.

**Non-Goals:**
- Changing the index formats or detection logic (the `Marshal`/`Load*` bytes are unchanged).
- OCR / clipboard / print index sources (separate DLP tickets, dependency/-display-gated).
- A signed-index *distribution* channel (the control plane already distributes files; signing is what
  makes distribution safe — the transport is out of scope).
- Key management/rotation for the operator key (same posture as the existing D100 rules key).

## Decisions

1. **Domain-separated detached signature over (kind, index), carried in a `SignedIndex` proto.**
   `sig = Ed25519.Sign(priv, "openshield-dlp-index\x1f" + kind + "\x1f" + index)`. The domain-separation
   prefix means an index signature can never be a valid rules signature (or vice versa), and binding
   `kind` means a signed EDM index presented in the IDM slot fails verification, not just parsing.
   `SignedIndex{ kind, index, signature }` mirrors `SignedRuleBundle`. Verify recomputes the signed
   bytes and checks the signature BEFORE the index bytes are ever parsed (an unverified index is never
   interpreted — the same ordering guarantee as `LoadSignedRules`).

2. **Verification gated by `OPENSHIELD_DLP_INDEX_PUBKEY`.** When the key is set, all three index files
   MUST be signed and verify (fail-closed: abort on unsigned/tampered/wrong-key/wrong-kind). When the
   key is unset, the legacy unsigned load is preserved but logs a loud warning naming the ADR-9 gap.
   This matches how signed rules (`OPENSHIELD_RULES_PUBKEY`), enroll pre-auth, and DPoP are gated —
   secure when configured, backward-compatible when not, never silently insecure.

3. **`VerifyIndex` returns the inner index bytes**, which the worker then feeds to the existing
   `LoadEDMIndex`/`LoadRecordIndex`/`LoadDocumentIndex`. The loaders' existing bounds checks (R34-8
   allocation guard) still apply to the verified bytes — signing does not bypass them.

4. **Operator tool `cmd/openshield-dlp-index build`**: `--type edm|record|idm`, `--in <file>`,
   `--key <ed25519-seed-or-pkcs8>`, `--out <file>`, plus type-specific knobs (EDM target-FP, record
   delimiter + threshold, IDM shingle-k + fraction). It reuses the SAME key-loading helper the other
   binaries use so an operator key works across rules and indexes. It reads plain input (one value/row/
   document per line or file), builds the index via the existing constructors, `Marshal()`s, and
   `SignIndex`es. Output is the exact bytes the worker verifies — the tool and the loader are tested
   against each other (round-trip).

## Risks / Trade-offs

- **Backward compatibility.** Turning the pubkey on requires re-issuing indexes as signed. That is the
  point (opt-in security); the warning in unsigned mode makes the gap visible without breaking anyone.
- **Key reuse across rules and indexes.** Domain separation makes reuse of one operator key safe (a
  signature for one context cannot validate in the other). Operators MAY use separate keys; the tool
  and worker do not force it.
- **Tool input formats.** Kept deliberately simple (line/row/document oriented). Richer sources (CSV
  quoting edge cases, binary docs) are follow-ons; the tool documents its input contract and rejects
  malformed input rather than guessing.
