## Why

DLP-3's EDM/multi-cell/IDM detection shipped REAL (D193/197/198), but two ADR-9 gaps remain, both
flagged in the roadmap status:

1. **The indexes shipped into the sandbox are UNSIGNED** — "inconsistent with ADR-9", which mandates
   "a signed index into the sandbox". The worker loads `OPENSHIELD_EDM_INDEX` / `_EDM_RECORD_INDEX` /
   `_IDM_INDEX` from files with no signature check. Anyone who can write those files (a compromised
   distribution path, a poisoned artifact) controls what the DLP detector matches — a poisoned index
   that matches nothing silently DISABLES exfil detection, one that matches everything is a DoS. This
   is the exact threat the signed custom-rules path (D100) already closes for detection *rules*; the
   detection *data* has no equivalent guard.
2. **There is no operator index-builder tool** — operators have no supported way to turn their
   sensitive values/records/documents into a (signed) index; today an index only exists if a test or
   ad-hoc code built one.

## What Changes

Mirror the D100 signed-rules model for DLP index data:

- **Signed-index envelope** (`internal/classify`): `SignIndex(kind, indexBytes, priv)` (operator
  authoring) and `VerifyIndex(signed, trustedPub, wantKind)` (node loading). Verification is
  fail-closed and domain-separated, and binds the index KIND so a signed EDM index cannot be loaded
  into the IDM slot. A new `SignedIndex` proto message carries `{kind, index, signature}`.
- **Worker verification**: when `OPENSHIELD_DLP_INDEX_PUBKEY` is set, every configured index file MUST
  be a signed index that verifies against that operator key before it is loaded into the sandbox — a
  missing/tampered/wrong-key/wrong-kind index ABORTS (fail-closed, exactly like signed rules). Without
  the key, legacy unsigned loading is preserved but logs a loud warning (the ADR-9 gap is opt-in-closed
  per deployment, matching the codebase's other security opt-ins).
- **Operator index-builder tool** (`cmd/openshield-dlp-index`): builds an EDM (one value per line),
  multi-cell record (delimited rows), or IDM (documents) index from operator input and SIGNS it with
  the operator key, emitting the exact bytes the worker verifies.

## Capabilities

### New Capabilities
- `signed-dlp-index`: signing, fail-closed verification, and operator authoring of the k-anonymized DLP
  detection indexes that ship into the sandbox — so a compromised distribution path cannot inject or
  poison the data the DLP detector matches against (ADR-9).

### Modified Capabilities
<!-- none: the EDM/IDM detection capability's REQUIREMENTS are unchanged; this adds a signing/authoring
     layer around the existing serialized indexes. -->

## Impact

- `internal/classify`: new `signed_index.go` (`SignIndex`/`VerifyIndex`) + `SignedIndex` proto message.
- `cmd/openshield-worker`: verify-before-load when `OPENSHIELD_DLP_INDEX_PUBKEY` is set; warn otherwise.
- `cmd/openshield-dlp-index`: new operator CLI (build + sign the three index kinds).
- No core change, no change to the index formats themselves (`Marshal`/`Load*` unchanged — the envelope
  wraps their bytes). One proto message added.
