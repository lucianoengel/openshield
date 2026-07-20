## Context

Phase 1 produces Decisions and records nothing. This change makes the recording real, and it is
the first change in the project involving cryptography, which changes what "getting it right"
means: a subtly wrong hash chain still passes casual tests while providing no guarantee.

The constraint that shapes everything: **the ledger is hash-chained, so schema changes are not
ordinary migrations.** Adding a column later changes what is hashed and breaks continuity at
that point. Columns required by D20 (retention, purpose, pseudonymous subject) and D27
(`context_version`) must exist at the first migration even though nothing writes them yet.

## Goals / Non-Goals

**Goals:** append-only hash-chained entries; key-evolving forward integrity; verification that
locates tampering and states what it does not cover; schema complete for later phases.

**Non-Goals:** external anchoring (T-019, interface accommodates it); retention enforcement
(T-013, columns only); evidence or content storage; investigation queries (T-010); multi-agent
chain reconciliation.

## Decisions

### Hash chain plus key evolution, not either alone

**Chosen:** each entry commits to its predecessor's hash, and each entry is signed with a key
that evolves forward, the prior key being destroyed.

Neither half is sufficient, and the reason is worth stating because a hash chain alone looks
convincing:

- **Chain alone:** an attacker who compromises the host holds the signing key and can rewrite
  the entire history consistently. The chain forces them to redo the tail; it does not stop them.
- **Key evolution alone:** entries are individually authentic but their order and completeness
  are unprotected — entries can be reordered or removed between valid signatures.

Together, the tail an attacker can rewrite begins at the moment of compromise. That is the whole
security claim, and it is a claim about the *past* only.

**Scheme: forward-secure SIGNATURES via evolving Ed25519 keypairs.**

The agent generates `KP_0` and publishes `PK_0` as the anchor. To evolve it generates `KP_n+1`,
signs `PK_n+1` with `SK_n`, then destroys `SK_n`. Entries are signed with the current private
key; verification walks the public-key chain from the anchor.

**This reverses an earlier decision in this same design, and the reason is worth recording.**

The first version specified Schneier-Kelsey symmetric ratcheting — `K_{n+1} = H(K_n)`, HMAC per
entry — chosen for simplicity and reviewability. It was implemented, and the implementation was
subtly wrong in a way its tests did not catch: the ledger retained the *seed* for the process
lifetime and derived each key with `KeyAt(seed, n)`, so the ratchet type that destroys keys was
never actually used. An attacker compromising the host obtained the seed and could forge all
history. Forward integrity was claimed and absent.

Fixing that bug exposed the real problem, which is structural rather than an implementation slip:

> **With a symmetric scheme, verification requires the seed — and the seed is a forging key.
> The only party who can verify the log is a party who can forge it.**

For this project specifically that is close to self-defeating:

- The control plane would hold every agent's seed, concentrating fleet-wide forgery in one box.
- The endpoint could not verify its own log (T-010's CLI would need the forging key).
- A **single-node air-gapped deployment cannot split the trust domain at all** — there is no
  second domain — so the guarantee evaporates in precisely the deployment shape the project
  advertises as air-gap friendly.
- No third-party verification: an auditor could only check the log by being handed the ability
  to fake it.

Asymmetric forward-secure signatures remove the forging key entirely. Verification needs only
public material, so the endpoint, an auditor or a regulator can all check the chain, and T-019's
anchoring becomes cheaper because the anchored value is public.

**Costs, stated plainly.** Ed25519 signing is ~50µs against HMAC's ~1µs — irrelevant here,
because append happens *after* a Decision rather than inside the permission window. The real
cost is complexity: keypair chain storage and epoch rollover, against D7's warning that
maintenance burden is what killed the predecessors. Bounded by evolving per **epoch** rather
than per entry (the compromise window becomes the epoch length) and by `crypto/ed25519` being
standard library, so no dependency is added.

**Rejected: Ma-Tsudik forward-secure sequential aggregate signatures.** The aggregate property
buys constant-size proofs over many entries, which this project does not need, at the cost of a
construction that is much harder to review. Reviewability remains a security property here.

**Rejected: TESLA-style delayed key disclosure.** A reverse hash chain (`K_n = H(K_n+1)`) gives
public verifiability, but disclosing `K_n` reveals every *earlier* key — the exact opposite of
forward integrity. Recorded because it is a plausible-looking wrong turn.

### Verification returns a structured result, never a boolean

**Chosen:** verification returns the validated range, the index of the first break if any, and
the anchor state.

A boolean invites the confusion that matters most: internal consistency is *not* completeness.
Between anchors, a root attacker can destroy the chain and build a shorter consistent one, which
verifies perfectly. A result that cannot express "consistent but completeness unverified" would
let a caller report a guarantee nobody has.

### Postgres is the system of record; the interface lives in core

**Chosen:** `core.Ledger` interface; `internal/store/postgres` implements it; `check-core-deps.sh`
extended so core cannot import a driver.

Same pattern and same reasoning as the transport boundary (D24). JetStream remains a bus and is
explicitly not the record — bounded retention is not a system of record (D12).

### Append is synchronous and its failure is fatal to the Decision path

**Chosen:** a failed append returns an error to the caller.

The tempting alternative — buffer in memory and retry — turns an unrecorded Decision into a
silent one, and in an observe-only product an unrecorded Decision is indistinguishable from an
event that never happened. When T-024 provides the durable queue, buffering becomes legitimate
because the buffer itself is durable. Until then, an error is the honest answer.

**Cost, stated plainly:** the agent needs a reachable database to record anything. That is a
real deployment constraint and it is worse than it sounds for an endpoint agent — it is one of
the reasons T-024 matters more than its ticket size suggests.

## Risks / Trade-offs

- **A subtly wrong chain passes casual tests.** → Verification is tested against *specific*
  attacks — edit, delete, reorder, truncate, and forging an early entry with a later key —
  rather than by round-tripping a valid chain.
- **Key material handling is the weak point.** Destroying the prior private key means
  overwriting it in memory, which Go's GC makes best-effort rather than guaranteed. → Documented
  honestly rather than claimed; the realistic protection is that the window is short, and a root
  attacker reading agent memory has already won on other fronts.
- **Epoch length is a direct security parameter.** Everything within the current epoch is
  forgeable by whoever compromises the host. → Must be configurable and its meaning documented
  where an operator will see it, not buried in code.
- **A test can encode an assumption the implementation contradicts.** The forward-integrity test
  passed against a *derived* key while the real attacker got the seed. → The replacement test
  must model the attacker taking everything the process holds, not a convenient subset.
- **Requiring a database contradicts "offline-capable".** → True and unresolved until T-024.
  Recorded here rather than left for someone to discover.
- **Forward integrity is unverifiable by an outside party without anchors.** → Precisely why the
  verification result reports anchor state, and why T-019 is not optional in the long run.

## Migration Plan

Forward-only numbered migrations. The first migration must be complete for later phases; there
is no cheap second chance. Order: schema → chain → key evolution → verification → attack tests →
CI dependency check.

## Open Questions

1. **Where does the current private key live at rest?** A file with restrictive permissions is
   the obvious answer and is weak against the root attacker already assumed to win. Deferred to
   T-012's sandbox hardening. Note this is now a smaller problem than before: the key at rest
   compromises only the current epoch forward, not all history.
4. **How is `PK_0` distributed so verification is meaningful?** A verifier who takes the anchor
   from the same host that could have rewritten it gains little. This is the same gap T-019
   closes for the chain root, and the two should probably share a mechanism.
2. **Chain-per-agent or chain-per-host?** Per-agent is simpler and matches the per-agent sequence
   numbers in the event contract. Revisit if an agent is ever restarted with a new identity.
3. **What does verification do about a legitimate gap** — an agent offline for a week? Currently
   indistinguishable from suppression. Needs T-018's heartbeat to resolve, and is the reason
   heartbeat is not merely an operational nicety.
