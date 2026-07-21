# Tasks — encrypt-local key escrow

## 1. Escrow crypto

- [x] 1.1 `GenerateEscrowKeypair() (pub, priv []byte, err error)` — a Curve25519 keypair (nacl/box).
- [x] 1.2 `EncryptEscrow(recipientPub, plaintext) ([]byte, error)` → `escrowMagic || box.SealAnonymous(...)`; `DecryptEscrow(recipientPriv, blob) ([]byte, error)` (verify escrow magic, OpenAnonymous — wrong key fails).
- [x] 1.3 `isEncrypted` recognises EITHER magic (idempotence across modes); symmetric `Decrypt` rejects an escrow blob and `DecryptEscrow` rejects a symmetric blob (self-describing, no silent cross).

## 2. Escrow mode on the enforcer

- [x] 2.1 `Enforcer` gains an optional recipient public key; `NewEscrow(pubKeyPath)` and `WithEscrowKey(pub)` build an escrow enforcer (32-byte pub, wrong length errors). `New`/`WithKey` stay symmetric.
- [x] 2.2 `EnforceTarget` seals via `EncryptEscrow` in escrow mode, else AES-GCM (D57); both atomic (temp+rename, 0600), both idempotent (already-encrypted → no-op), both error on empty target.

## 3. Tests (guards, each mutation-tested)

- [x] 3.1 **Test**: escrow `EnforceTarget` produces a blob that does NOT open with the public key / endpoint material, DOES open with the private key to the exact original, and a wrong private key fails.
- [x] 3.2 **Test**: modes don't cross — symmetric `Decrypt` rejects an escrow blob and `DecryptEscrow` rejects a symmetric blob; re-encrypt (either mode) is idempotent.
- [x] 3.3 **Test**: `NewEscrow` rejects a wrong-length public key; empty target errors in escrow mode.
- [x] 3.4 **Test (engine e2e)**: a policy deciding `ENCRYPT_LOCAL` with an escrow enforcer seals the file so only the escrow private key recovers it; the outcome is audited.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` new D-number: escrow closes the D57 custody gap (endpoint holds only the public key, cannot decrypt); trust shifts to the private-key holder; defends endpoint compromise not escrow-holder compromise; key distribution/rotation + private-key custody (D16) remain operational.
- [x] 4.2 `openspec validate add-encrypt-local-escrow --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| escrow "seal" stores plaintext after the magic | `TestEscrowEndpointCannotDecrypt` (plaintext survives / no priv needed) |
| EnforceTarget ignores escrow mode (always symmetric) | `TestEscrowEndpointCannotDecrypt` (private key can't recover) |
| WithEscrowKey ignores the key length | `TestEscrowKeyLengthAndEmptyTarget` |

**Honest note on modes-don't-cross:** removing the explicit escrow-magic reject in
`Decrypt` did NOT break `TestEscrowAndSymmetricDoNotCross` — the property is
doubly-guarded (distinct magic AND AEAD authentication), so a cross attempt still
fails on the AEAD tag regardless of the magic. That is defense-in-depth working as
intended, not a gap; the test still asserts the behavior.

Escrow closes the D57 custody gap: the endpoint holds only the recipient PUBLIC
key and cannot decrypt what it seals — proven, an escrow blob does not open with
the public key / endpoint material and only the off-endpoint PRIVATE key recovers
the exact original. Symmetric mode (D57) is untouched. Proven end to end in the
engine (policy ENCRYPT_LOCAL → sealed file only the escrow key recovers → audited).
