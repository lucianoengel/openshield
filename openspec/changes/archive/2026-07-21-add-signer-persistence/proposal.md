# Add signer persistence for ledger write-resume (T-009 seam)

## Why

The audit ledger cannot resume WRITING across a restart. `postgres.Open` refuses a signer whose
anchor does not match the stored chain (`ErrCannotResumeWriting`), and today every restart brings a
FRESH signer — a new anchor — so a restarted agent cannot continue its own chain. The public-key
chain is persisted (`key_epochs`), but the CURRENT private key lives only in memory, so nothing can
reconstruct the signer. In practice that means a restart either forks a second chain or refuses to
write. For an append-only evidentiary log, "cannot continue after a reboot" is a real hole (it is
the write half of the D31/T-017-adjacent gap the ledger flagged).

## What changes

**The signer's current state becomes exportable and reloadable.** `Signer.Export()` serialises the
CURRENT private key, the epoch counter, and the public-key chain; `core.LoadSigner(blob)`
reconstructs an identical signer. A process that reloads a signer from its own export has the same
anchor as the stored chain, so `postgres.Open` accepts it and appends continue the chain — no fork,
no refusal.

**Only the CURRENT epoch's private key is persisted — never the destroyed ones.** This is
consistent with the forward-security model (D30): the current epoch is already the compromise
window (its key must exist to sign), and every earlier private key was destroyed on evolution and
is absent from the export. Reloading restores exactly the writing capability the running agent
already had, and no more.

**A file helper persists it with restrictive permissions.** `SaveSignerFile(path, signer)` writes
the export atomically at mode 0600; `LoadSignerFile(path)` reads it back. The agent persists its
signer state to a private file and reloads it on start.

## What this does NOT claim or cover

- **At-rest protection is filesystem permissions, not encryption.** The file is 0600 and owned by
  the agent user; a host attacker with root reads it (D16), exactly as they could read the key from
  the running process's memory. The honest guarantee is unchanged: the current epoch is forgeable
  by whoever takes the host, the past is not. Encrypting the file at rest (with a key from a TPM or
  an operator secret) is a hardening follow-up, noted — it would not change the threat model, only
  raise the bar against offline disk theft.
- **It does not persist old private keys** — by design; that would destroy forward security. Only
  the current epoch is reloadable.
- **It does not add key rotation or re-enrolment.** The signer resumes as it was; T-017's identity
  key persistence is a sibling gap (the agent's identity vs the ledger's signer are distinct keys),
  addressed the same way but separately.
- **It does not change verification.** Verification already takes only public material; this is the
  write path. A reloaded signer produces the same chain a continuous process would have.

## Decisions

Depends on **D30** (the forward-secure signer; only the current key exists), **D32** (the persisted
public chain), and the `ErrCannotResumeWriting` boundary the ledger already draws.

Establishes a small new decision: **the ledger signer's CURRENT state (current private key, epoch,
public chain) is exportable and reloadable so an agent resumes its own chain across a restart;
at-rest protection is 0600 file permissions, defeated by host root exactly as memory is, with
encryption-at-rest a noted hardening follow-up.**
