## Why

Enforcement (D49) proved the post-decision dispatch seam with two enforcers:
quarantine (move a file) and usb (attach-time allow/deny). `ACTION_ENCRYPT_LOCAL`
is already in the closed action set (D14), but nothing carries it out — so the
one action whose whole point is to render a flagged file UNREADABLE has no
implementation. Adding it exercises a genuinely different enforcement primitive
(cryptographic transformation in place, not relocation) against the same seam.

## What Changes

- A new `internal/enforcers/encryptlocal` enforcer implements `core.Enforcer` +
  `core.TargetedEnforcer`, advertises `Capabilities() = [ENCRYPT_LOCAL]`, and
  errors (never silently no-ops) when given no target.
- `EnforceTarget` encrypts the flagged file IN PLACE with AES-256-GCM (a random
  per-file nonce), written atomically (temp + rename) so the original plaintext
  is replaced, with a magic header so re-encrypting an already-encrypted file is
  idempotent (not double-encrypted or corrupted).
- A package `Decrypt(key, blob)` function supports operator recovery and lets
  tests PROVE the ciphertext round-trips to the exact original bytes and that a
  wrong key fails (GCM authentication) — the file is genuinely unreadable without
  the key, not merely renamed.
- The enforcer is wired as a registrable engine enforcer; an end-to-end test
  proves a policy deciding `ENCRYPT_LOCAL` routes to it, the file ends up
  encrypted on disk, and the enforcement outcome is audited (D14, never silent).

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `enforcement`: add the encrypt-local action — the engine can dispatch
  `ENCRYPT_LOCAL` to an enforcer that renders the flagged file unreadable in
  place, audited like any enforcement.

## Impact

- New code: `internal/enforcers/encryptlocal` (enforcer + Encrypt/Decrypt +
  key-file load). Registrable via the engine's existing `Enforcers` slice; no
  change to the Decision contract or the dispatch path.
- CONTAINMENT after detection, not prevention (the file was already read to be
  classified) — same honesty as quarantine. Encryption's value depends on KEY
  CUSTODY: an on-host key readable by the agent user defends against a stolen
  disk or a different user, NOT against the agent user or host root (D16), the
  same bar as the signer key. Stated in docs, not overclaimed. D14 holds.
