## ADDED Requirements

### Requirement: A witnessed anchor attests to the ledger head
The ledger MUST support a witness-signed anchor recording a `(sequence, hash)` checkpoint, signed
by a key in a different trust domain than the ledger signer. Verifying an anchor MUST require only
public material.

An anchor the agent could forge proves nothing, because the agent is the party that might rewrite
the log. The witness signature — from a domain the deployer does not control — is what makes an
anchor evidence rather than decoration. Because the chain is linear, a checkpoint of the head hash
attests to the whole prefix without an inclusion proof.

#### Scenario: An anchor verifies with the witness public key alone
- **WHEN** a witness anchors the current head and the anchor is verified with the witness public key
- **THEN** verification succeeds using no secret
- **AND** an anchor signed by the wrong key fails

### Requirement: Verification proves completeness only through the last anchor
Given valid anchors, verification MUST confirm each anchor's `(sequence, hash)` matches the chain,
report the highest witnessed sequence as `AnchoredThrough`, and mark completeness ANCHORED only
when the whole chain is witnessed — leaving the tail after the last anchor UNVERIFIED.

Completeness is provable only where a witness attests to it. The prefix up to the last anchor
cannot be truncated undetectably; everything after it still can. A verifier MUST be told that
exact boundary rather than a single yes/no, or it will mistake "the witnessed prefix is complete"
for "nothing was removed".

#### Scenario: A partially-anchored chain reports the boundary
- **WHEN** a chain has an anchor at sequence N and further un-anchored entries after N
- **THEN** verification reports `AnchoredThrough = N` and completeness UNVERIFIED overall
- **AND** a test asserts the prefix is reported anchored and the tail unverified

#### Scenario: A fully-anchored chain is complete
- **WHEN** an anchor covers the last entry
- **THEN** completeness is ANCHORED

### Requirement: Truncation of witnessed history is detected
If the chain is truncated or rebuilt shorter than a valid anchor's sequence, verification MUST
fail, naming the anchor whose checkpoint is no longer satisfied.

This is the property anchoring exists to add: destroying WITNESSED history is caught. Destroying
unwitnessed history — the tail since the last anchor — still is not, and that residual window
equals the anchor interval and MUST be documented where the interval is configured.

#### Scenario: A chain rebuilt shorter than an anchor fails
- **WHEN** an anchor attests sequence N but the chain now ends before N (or entry N's hash differs)
- **THEN** verification fails and names the violated anchor
- **AND** a test rebuilds a shorter chain past an anchor and asserts detection

#### Scenario: No-anchor behaviour is unchanged
- **WHEN** verification runs with no anchors
- **THEN** it behaves exactly as before — completeness UNVERIFIED — so anchoring is purely additive
