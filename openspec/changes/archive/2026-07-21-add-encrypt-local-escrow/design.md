## Context

`encryptlocal` (D57) has `Encrypt`/`Decrypt` (AES-256-GCM, symmetric) and an
`Enforcer` with `EnforceTarget` that seals a file in place with a magic header,
atomic temp+rename, idempotent. The enforcer holds the key. This adds a second
mode that holds only a PUBLIC key, so the endpoint cannot decrypt what it wrote.

## Goals / Non-Goals

**Goals:**
- The endpoint can encrypt but not decrypt; recovery needs an off-endpoint
  private key.
- Prove that property in tests, not just assert it.
- Coexist with symmetric mode; blobs are self-describing (distinct magic).
- Preserve every D57 invariant.

**Non-Goals:**
- Delivering the private key anywhere, or building the escrow vault / a fetch
  protocol — the private key's custody is out of scope (an operator holds it).
- Key rotation / re-wrapping / multi-recipient — single recipient public key.
- Replacing symmetric mode.

## Decisions

**`nacl/box` anonymous sealed-box (`box.SealAnonymous` / `box.OpenAnonymous`).**
It is exactly public-key escrow: the sender is anonymous (an ephemeral keypair is
generated per message and its public part embedded), the recipient decrypts with
their Curve25519 private key. The endpoint needs ONLY the recipient's 32-byte
public key to seal. No shared secret is ever on the endpoint. Minimal, audited,
already in go.sum.

**On-disk format: `escrowMagic || sealed`.** A DISTINCT magic (`OSENCX1\x00` vs
the symmetric `OSENC1\x00`) so a blob is self-describing: `isEncrypted` (either
magic) still drives idempotence, and recovery tooling can tell which key it
needs. `DecryptEscrow` verifies the escrow magic and `box.OpenAnonymous`s the
rest with the recipient keypair.

**Escrow is a MODE, selected at construction.** `Enforcer` gains an optional
recipient public key; `NewEscrow(pubKeyPath)` / `WithEscrowKey(pub)` build an
escrow enforcer, `New(keyPath)` / `WithKey` stay symmetric. `EnforceTarget`
branches on the mode: seal-anonymous in escrow mode, AES-GCM in symmetric mode.
Both write atomically, both are idempotent (already-encrypted → no-op regardless
of which magic), both error on empty target. One enforcer type, one dispatch
path; the mode is an internal detail the engine does not see.

**`GenerateEscrowKeypair()` returns (public, private).** The operator runs it
once, provisions the public key to endpoints, and stores the private key in the
vault. Exporting it keeps provisioning in the package and lets tests generate a
real keypair to prove the round trip.

**Recovery is `DecryptEscrow(privateKey, blob)`.** It needs the private key, so a
test that has only the public key CANNOT recover — which is the property we want
to demonstrate. Symmetric `Decrypt` is unchanged and rejects an escrow blob (and
vice-versa) via the magic, so the two modes never silently cross.

## Risks / Trade-offs

- **Trust moves to the private-key holder.** Escrow defends against ENDPOINT
  compromise, not against compromise of whoever holds the private key. That is
  the honest boundary and is stated as such — an improvement in WHERE the trust
  sits (off the endpoint), not a claim of invulnerability.
- **Private-key custody is now the critical asset (D16).** If it leaks, every
  escrowed file is exposed; if it is lost, every escrowed file is unrecoverable.
  Backup/rotation is an operational concern, documented, not solved here.
- **No sender authentication.** Anonymous sealed-box gives confidentiality to the
  recipient but does not prove WHO sealed it. That is acceptable: the enforcement
  outcome is separately recorded in the tamper-evident ledger (D14/D30), which is
  where authenticity of the ACTION lives; the escrow blob only needs to be
  confidential and recoverable.
