## Context

`Signer{ epoch uint64; priv ed25519.PrivateKey; chain []KeyEpoch }`. The chain is persisted in
`key_epochs`; `priv` and `epoch` are memory-only. `postgres.Open` on a non-empty DB requires
`signer.AnchorKey().Equal(storedAnchor)`, else `ErrCannotResumeWriting`. A fresh signer has a new
anchor, so resume fails.

## Goals / Non-Goals

**Goals:**
- Serialise/reload the CURRENT signer state so a restarted process resumes its chain.
- Persist only the current epoch's private key; never a destroyed one.
- A 0600 file helper; the reloaded signer passes Open's anchor check and appends continue the chain.

**Non-Goals:**
- Encryption at rest (noted hardening); old-key persistence (would break forward security); identity-
  key persistence (sibling gap); verification changes.

## Decisions

### Export/Load a SignerState
```go
type SignerState struct {
    Epoch uint64
    Priv  []byte          // CURRENT epoch private key only
    Chain []KeyEpoch      // public material
}
func (s *Signer) Export() ([]byte, error)     // gob-encode SignerState
func LoadSigner(blob []byte) (*Signer, error) // decode + reconstruct, validating shape
```
Encoding: `encoding/gob` (stdlib, not banned in core). LoadSigner validates: non-empty chain, a
private key of `ed25519.PrivateKeySize`, `epoch < len(chain)` and `chain[epoch]`'s public key
matches the private key's public half — so a corrupted or mismatched blob fails to load rather than
producing a signer that signs under a key the chain does not list.

### The reloaded signer is not "foreign"
`Open` compares `signer.AnchorKey()` (chain[0]) to the stored anchor. A reloaded signer has the
identical chain[0], so it matches and resume proceeds. `resumeTail` sets seq/prev from the DB;
`persistedEpoch` is the DB max; the signer's epoch may equal or be one ahead (evolve-after-commit
persists the new epoch lazily on the next append) — both handled by existing `persistEpochsThrough`.

### File helper, atomic + 0600
`SaveSignerFile(path, s)`: export, write to `path+".tmp"` at 0600, rename (atomic). `LoadSignerFile`
reads and LoadSigner. The agent calls Save after Open/Evolve and Load on start. Atomic write so a
crash mid-save leaves the old file intact.

### Sensitivity, stated
The blob holds the current private key. 0600 + agent-user ownership is the at-rest control; host
root defeats it (D16), the same bar as reading process memory. Encryption at rest (TPM/operator
secret) is a documented follow-up that raises the bar against offline disk theft only.

## Risks / Trade-offs

- **gob is not a canonical/hostile-input format.** It decodes our own trusted export, not attacker
  input, so gob's caveats do not apply here; LoadSigner still validates shape so a corrupt file is a
  clean error, not a panic.
- **Persisting a private key at all** widens the attack surface from memory to disk. Bounded to the
  current epoch (the existing compromise window) and 0600; the alternative (no write-resume) is a
  worse hole for an evidentiary log. Stated.
- **Save timing.** If the agent evolves and crashes before saving, the reloaded signer is one epoch
  behind; the next append persists the newer epoch's public row and the older private key can still
  sign the pending entry — no chain break, just a slightly wider window. Bounded and noted.
