## Context

The engine dispatches a recorded Decision to the first registered enforcer whose
`Capabilities()` advertises the action, supplying the target path for a
`TargetedEnforcer` (D49). Quarantine is the template: `Capabilities()`, an
`Enforce` that errors without a target, and an `EnforceTarget(ctx, decision,
target)` that acts on the file. Encrypt-local follows the same shape but replaces
the file's CONTENTS rather than its location.

## Goals / Non-Goals

**Goals:**
- Carry out `ENCRYPT_LOCAL` by making the flagged file unreadable in place with
  an authenticated cipher.
- Prove it genuinely: ciphertext ≠ plaintext, recoverable ONLY with the key, and
  a wrong key fails (GCM auth) — not a rename dressed up as encryption.
- Atomic and idempotent: a crash mid-encrypt does not truncate the file, and a
  re-encrypt does not double-encrypt.
- Honest about custody and containment (D16, D49).

**Non-Goals:**
- Key management / escrow / rotation — the key is loaded from a file, custody is
  the operator's concern (documented). No KMS.
- Prevention — the file was already read; this contains after the fact.
- Encrypting anything but the single targeted file.

## Decisions

**AES-256-GCM, random 12-byte nonce per file.** GCM gives confidentiality AND
integrity: a wrong key or a tampered blob fails to open, which is what lets the
test assert the file is truly unreadable without the key. The nonce is fresh per
encryption (crypto/rand) and stored alongside the ciphertext.

**On-disk format: `magic || nonce || ciphertext`.** The magic (`OSENC1\x00`)
marks an OpenShield-encrypted file so `EnforceTarget` can be IDEMPOTENT: if the
target already begins with the magic, it is already contained — return success
without re-encrypting (double-encryption would still be recoverable but wastes
work and complicates recovery). `Decrypt` verifies the magic, splits the nonce,
and opens the ciphertext.

**Atomic replace.** Encrypt to `target.tmp` (0600) then `os.Rename` over the
target, so a crash leaves either the original or the fully-encrypted file, never
a half-written one — the same discipline as `SaveSignerFile`.

**Key from a file, 32 bytes.** `New(keyPath)` reads exactly 32 bytes (raw or
hex — decide raw for simplicity; a wrong length is a load error). At-rest
protection is filesystem perms + the agent user (D16). This is deliberately the
SAME bar as the signer key — encrypt-local does not claim to defend against the
agent user or host root; its honest value is a stolen disk or a different local
user.

**Decrypt is exported.** Recovery is a real operation (an operator must be able
to get the file back), and exporting it also lets the guard test prove the round
trip against the real cipher rather than an internal shortcut.

## Risks / Trade-offs

- **Key custody decides the value.** If the key sits next to the encrypted files
  readable by the same user, an attacker with that user reads both — encryption
  buys little against them. It buys real protection against an OFFLINE attacker
  (stolen disk) or a DIFFERENT user. This is stated plainly; overclaiming here
  would be exactly the kind of unbacked security claim the project guards against.
- **In-place encryption is destructive.** If the key is lost, the file is gone.
  Mitigated by atomic write (no partial states) and by recovery via `Decrypt`;
  key backup is the operator's responsibility (documented).
- **Containment, not prevention (D49).** The file was already read to be
  classified. Encrypt-local contains it afterward; it does not stop the access.
