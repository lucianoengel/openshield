# Add external anchoring for completeness (T-019)

## Why

Every `Verify` today reports `completeness=UNVERIFIED`, and honestly so: the hash chain and
forward-secure signatures prove that recorded history was not ALTERED, but not that it was not
TRUNCATED. A root attacker can destroy the chain and rebuild a shorter, internally-consistent one
that verifies perfectly — the ledger says this in `VerifyResult` and the CLI prints it on every
run. D12 named external anchoring as the missing piece, and T-009 deferred it here.

Anchoring closes the gap only where a witness OUTSIDE the deployer's control attests to what the
ledger contained at a moment. This change builds that mechanism and, crucially, keeps the honest
boundary sharp: completeness becomes provable BETWEEN anchors, and the unanchored tail stays
exactly as unverified as it is today.

## What changes

**A witnessed anchor: a signed checkpoint of the ledger head.** An `Anchor` records `(sequence,
hash)` — the ledger's latest entry at a moment — signed by a WITNESS key that lives in a
different trust domain than the agent (a second host, WORM storage, or a public transparency
service). The witness signature is what makes an anchor evidence: a checkpoint the agent could
forge would prove nothing, because the agent is the party that might rewrite the log.

**Verification integrates anchors and reports what they prove — and what they don't.** Given a
set of valid anchors, `VerifyChain` confirms each anchor's `(sequence, hash)` matches the chain,
and sets `AnchoredThrough` to the highest witnessed sequence. Completeness becomes ANCHORED only
for the prefix up to that sequence; everything after the last anchor remains UNVERIFIED, because
nothing witnesses it yet. A verifier is told the exact boundary: "complete through sequence N,
unverified after."

**A truncation to before the last anchor is now DETECTED.** If the chain is rebuilt shorter than
an anchor's sequence, the anchored `(sequence, hash)` no longer matches — verification fails,
naming the anchor. This is the property the whole ticket exists to add: destroying witnessed
history is now caught, where destroying unwitnessed history still is not.

**The witness is pluggable; Phase 1 ships a local second-domain witness.** The anchor store and a
witness keypair held separately from the signer demonstrate the mechanism end to end. A real
external witness (another org's transparency log, object-lock storage) is deployment
configuration — the interface is the same, and the honest limit (an anchor is only as
trustworthy as the independence of its witness) is documented, not hidden.

## What this does NOT claim or cover

- **It does not make the ledger tamper-proof.** It makes truncation of WITNESSED history
  detectable. The unanchored tail — everything since the last anchor — can still be destroyed
  undetectably, and verification says so with `AnchoredThrough`. The window of undetectable loss
  is the anchor interval, and that is stated wherever the interval is configured (the same honesty
  D30 applies to the epoch).
- **It does not provide a real third-party witness.** Phase 1's witness is a separate keypair to
  prove the mechanism; genuine external witnessing (a domain the deployer truly does not control)
  is a deployment choice. An anchor witnessed by a key the deployer holds is theatre, and the docs
  say so.
- **It does not anchor automatically on a schedule.** The mechanism to produce and verify anchors
  is built; wiring a periodic anchor job to a real witness is where the deployment integration
  lands. Producing an anchor on demand is supported and tested.
- **It is not a Merkle tree.** The ledger is a linear hash chain, so an anchor over the head hash
  already commits to the whole prefix; a Merkle root would add inclusion proofs the linear chain
  does not need. Stated so the simpler structure is a choice, not an oversight.

## Decisions

Depends on **D12** (external anchoring names the completeness gap), **D30** (the forward-secure
chain the anchor checkpoints), and **D32** (verification takes public material; an anchor is
public and witness-signed).

Establishes a new decision: **completeness is proven only between witnessed anchors; the
unanchored tail is reported as unverified via `AnchoredThrough`, and an anchor is only as
trustworthy as the independence of its witness** — the honest boundary D12 required.
