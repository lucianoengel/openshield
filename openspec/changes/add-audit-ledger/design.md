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
that ratchets forward, the prior key being destroyed.

Neither half is sufficient, and the reason is worth stating because a hash chain alone looks
convincing:

- **Chain alone:** an attacker who compromises the host holds the signing key and can rewrite
  the entire history consistently. The chain forces them to redo the tail; it does not stop them.
- **Key evolution alone:** entries are individually authentic but their order and completeness
  are unprotected — entries can be reordered or removed between valid signatures.

Together, the tail an attacker can rewrite begins at the moment of compromise. That is the whole
security claim, and it is a claim about the *past* only.

**Scheme:** Schneier-Kelsey style ratcheting — `K_{n+1} = H(K_n)`, `K_n` destroyed after use.
Chosen over Ma-Tsudik forward-secure sequential aggregate signatures because the aggregate
property (constant-size proof over many entries) buys compactness this project does not need,
at the cost of a construction that is harder to implement correctly and much harder for the
maintainer to review. Given the maintainer does not write code, "reviewable" is a security
property here, not a preference.

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
- **Key material handling is the weak point.** Destroying the prior key means overwriting it in
  memory, which Go's GC makes best-effort rather than guaranteed. → Documented honestly rather
  than claimed; the realistic protection is that the window is short, and a root attacker
  reading agent memory has already won on other fronts.
- **Requiring a database contradicts "offline-capable".** → True and unresolved until T-024.
  Recorded here rather than left for someone to discover.
- **Forward integrity is unverifiable by an outside party without anchors.** → Precisely why the
  verification result reports anchor state, and why T-019 is not optional in the long run.

## Migration Plan

Forward-only numbered migrations. The first migration must be complete for later phases; there
is no cheap second chance. Order: schema → chain → key evolution → verification → attack tests →
CI dependency check.

## Open Questions

1. **Where does the ratcheting key live at rest?** A file with restrictive permissions is the
   obvious answer and is weak against the root attacker who is already assumed to win. Deferred
   to T-012's sandbox hardening.
2. **Chain-per-agent or chain-per-host?** Per-agent is simpler and matches the per-agent sequence
   numbers in the event contract. Revisit if an agent is ever restarted with a new identity.
3. **What does verification do about a legitimate gap** — an agent offline for a week? Currently
   indistinguishable from suppression. Needs T-018's heartbeat to resolve, and is the reason
   heartbeat is not merely an operational nicety.
