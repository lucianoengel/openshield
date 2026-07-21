## Why

D57's encrypt-local uses a SYMMETRIC key loaded from an on-host file, and the
decision said the honest limit plainly: an on-host key readable by the agent user
or host root defeats it — a fully-compromised endpoint holds both the ciphertext
AND the key, so encryption buys nothing against that attacker. That is the exact
gap this closes.

## What Changes

- A new ESCROW mode for the encrypt-local enforcer using PUBLIC-KEY (envelope)
  encryption: the endpoint is provisioned with only the RECIPIENT PUBLIC key of an
  escrow keypair (Curve25519, `nacl/box` anonymous sealed-box). The enforcer can
  ENCRYPT but CANNOT DECRYPT — recovery needs the recipient PRIVATE key, held OFF
  the endpoint (control plane / operator vault).
- So an attacker who fully compromises the endpoint gets the ciphertext, the
  sealed blob, and the public key — none of which decrypts the file. Only the
  offline/remote private key does.
- It is a MODE of the existing enforcer, not a rewrite: symmetric mode (D57)
  stays for the simple case; escrow mode (`NewEscrow` with a recipient public-key
  file) is opt-in, with a DISTINCT magic header so escrow and symmetric blobs are
  self-describing and recovery routes correctly.
- `GenerateEscrowKeypair()` provisions a keypair; `DecryptEscrow(privateKey,
  blob)` recovers. Tests PROVE the endpoint-holds-only-public property: an escrow
  blob does NOT open with the public key / endpoint material, DOES with the
  private key (exact round trip), and a wrong private key fails.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `enforcement`: add an escrow mode to encrypt-local — the endpoint seals flagged
  files to a recipient public key and cannot itself decrypt them; recovery
  requires the off-endpoint private key.

## Impact

- New code in `internal/enforcers/encryptlocal`: `EncryptEscrow`/`DecryptEscrow`,
  `GenerateEscrowKeypair`, `NewEscrow(pubKeyPath)`; a distinct escrow magic;
  `EnforceTarget` seals in escrow mode. Registrable via the engine's `Enforcers`
  slice, no Decision-contract change. Dependency: `golang.org/x/crypto/nacl/box`
  (already in go.sum).
- D57 invariants preserved (atomic temp+rename, idempotent via magic,
  empty-target errors, containment-not-prevention).
- HONEST residual: escrow shifts trust to whoever holds the PRIVATE key — it
  defends against ENDPOINT compromise, not against compromise of the escrow
  holder; and escrow-key distribution/rotation and the private key's own at-rest
  custody (D16) remain operational concerns. D14 holds.
