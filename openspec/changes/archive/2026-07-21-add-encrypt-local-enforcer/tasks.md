# Tasks — encrypt-local enforcer

## 1. Crypto core

- [x] 1.1 `internal/enforcers/encryptlocal`: `Encrypt(key, plaintext) []byte` (magic || nonce || AES-256-GCM ciphertext) and `Decrypt(key, blob) ([]byte, error)` (verify magic, split nonce, open — wrong key/tamper fails).
- [x] 1.2 `isEncrypted(blob) bool` — the magic-header check for idempotence.

## 2. The enforcer

- [x] 2.1 `Enforcer` with a 32-byte key; `New(keyPath)` loads exactly 32 bytes (wrong length → error). Implements `core.Enforcer` + `core.TargetedEnforcer`; `Capabilities() = [ENCRYPT_LOCAL]`.
- [x] 2.2 `Enforce` without a target returns an error (never a silent no-op). `EnforceTarget` reads the file, returns success unchanged if already encrypted (idempotent), else writes `Encrypt(...)` atomically (temp + rename, 0600) over the target.

## 3. Tests (guards, each mutation-tested)

- [x] 3.1 **Test**: `EnforceTarget` makes on-disk bytes ≠ plaintext; `Decrypt` with the right key recovers EXACT original bytes; a wrong key fails (GCM auth).
- [x] 3.2 **Test**: idempotent — encrypting an already-encrypted file leaves it recoverable to the original plaintext (not double-encrypted/corrupted).
- [x] 3.3 **Test**: empty target → error; `Capabilities()`/`CanEnforce` matches only `ENCRYPT_LOCAL`.
- [x] 3.4 **Test (engine e2e)**: a policy deciding `ENCRYPT_LOCAL` routes to the registered enforcer; the target file ends up encrypted on disk and the enforcement outcome is in the ledger.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` new D-number: encrypt-local is the second real enforcer (AES-256-GCM in place, atomic, idempotent, recoverable); containment not prevention; value depends on key custody, host root/agent user still win (D16); D14/D49 hold.
- [x] 4.2 `openspec validate add-encrypt-local-enforcer --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| EnforceTarget no-ops (never writes the ciphertext) | `TestEncryptsUnreadablyAndRecovers` |
| "encrypt" stores plaintext after the header (no cipher) | `TestEncryptsUnreadablyAndRecovers` (plaintext survives / wrong key opens) |
| not idempotent (always re-encrypt) | `TestIdempotentReEncrypt` |
| empty target no-ops instead of erroring | `TestEmptyTargetAndCapabilities` |

Encrypt-local is a genuine second enforcer: AES-256-GCM in place, atomic
temp+rename, idempotent via a magic header, and PROVEN unreadable — on-disk bytes
differ from the plaintext, a wrong key fails the GCM tag, and the right key
recovers the exact original. End to end, a policy deciding ENCRYPT_LOCAL routes
to the registered enforcer, the file is encrypted on disk, and the outcome is
audited (decision first, D14). Containment not prevention; value depends on key
custody (D16).
