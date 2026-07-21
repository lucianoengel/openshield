## Context

The ledger is a linear hash chain with forward-secure signatures. `VerifyChain` returns a
`VerifyResult` whose `Completeness` is UNVERIFIED without an anchor and ANCHORED with the existing
`anchored bool` flag — but nothing produces the evidence that would justify setting it, so it is
always UNVERIFIED in practice. Because the chain is linear, entry N's hash commits to the entire
prefix [0, N]; a checkpoint of (N, hash_N) therefore attests to everything up to N without needing
a Merkle inclusion proof.

## Goals / Non-Goals

**Goals:**
- A witness-signed anchor over the ledger head, verifiable with public material.
- Verification that sets `AnchoredThrough` to the highest witnessed sequence and reports
  completeness honestly: ANCHORED prefix, UNVERIFIED tail.
- Truncation to before an anchor is DETECTED.

**Non-Goals:**
- A real third-party witness (deployment config); automatic scheduled anchoring; a Merkle tree
  (the linear chain does not need one).

## Decisions

### Anchor and Witness
```go
type Anchor struct {
    Sequence   uint64
    Hash       []byte   // the head entry's hash at anchor time
    WitnessSig []byte   // Ed25519 over canonical(Sequence, Hash)
}
type Witness struct { priv ed25519.PrivateKey }   // lives in a DIFFERENT trust domain than the Signer
func (w *Witness) Anchor(seq uint64, hash []byte) Anchor
func VerifyAnchor(a Anchor, witnessPub ed25519.PublicKey) bool
```
The witness key is deliberately NOT the ledger signer: an anchor the agent could forge proves
nothing, because the agent is the party that might rewrite the log. The canonical bytes for the
witness signature are length-prefixed `(sequence, hash)`, same discipline as entry hashing.

### Verification integrates anchors
`VerifyChain` gains a `[]Anchor` and a witness public key (threaded via the postgres `Verify`
call, which loads stored anchors). Algorithm:
1. Verify the chain as today (links, content, signatures).
2. For each anchor: check `VerifyAnchor` (witness sig), then find the entry at `anchor.Sequence`
   and confirm its hash equals `anchor.Hash`. A valid anchor whose sequence is missing or whose
   hash mismatches is a TRUNCATION or rewrite → fail, naming the anchor.
3. `AnchoredThrough` = max sequence over satisfied anchors. Completeness = ANCHORED if
   `AnchoredThrough >= ToSequence` (the whole chain is witnessed), else UNVERIFIED with
   `AnchoredThrough` reported — the prefix is proven complete, the tail is not.

`VerifyResult` gains `AnchoredThrough uint64` (and keeps `Completeness`). The CLI header prints
"complete through N, unverified after" when anchored partially.

### Storage
Migration `004`: an `anchors` table `(sequence BIGINT, hash BYTEA, witness_sig BYTEA)`. postgres
`Verify` loads them and passes them to `VerifyChain` with the witness public key (configured
alongside the anchor key). `AnchorHead(ctx, witness)` reads the current head and appends an anchor.

### Honest boundary is documented where the interval lives
The undetectable-loss window equals the anchor interval — everything since the last anchor can be
truncated undetectably. This is stated in the anchor API docs and the decision record, the same
way the epoch is documented as the compromise window (D30).

## Risks / Trade-offs

- **A witness the deployer controls is theatre.** The mechanism cannot tell a truly independent
  witness from a captive one; the docs state that an anchor is only as trustworthy as its
  witness's independence. Phase 1's local witness proves the mechanism, not the trust.
- **Touching VerifyChain again.** Additive: anchors default empty, and with no anchors behaviour is
  byte-for-byte as today (completeness UNVERIFIED). Tested: a no-anchor chain verifies exactly as
  before; a satisfied anchor sets AnchoredThrough; a violated anchor fails.
- **The unanchored tail is still fully vulnerable.** By design and by physics — nothing witnesses
  it. Reported, not hidden.
