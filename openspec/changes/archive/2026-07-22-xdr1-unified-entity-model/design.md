## Context

Every domain already references a device by its canonical pseudonym (`pseudonym.Of(agentID)`, IDENT-1) —
telemetry, posture, the gateway subject. XDR-1 turns that shared key into an explicit entity: a row that
many aliases point to. The store is Postgres-backed (durable, server-side, the system of record like the
ledger) and must resolve aliases atomically under concurrent ingest.

## Goals / Non-Goals

**Goals**
- `entities` + `entity_aliases` schema; `Resolve(kind, value)` (atomic find-or-create); `Link` (merge).
- Prove the canonical join: two signals sharing `pseudonym.Of(A)` resolve to one entity; device ⋈ user.

**Non-Goals**
- Stamping/ingesting endpoint events with the pseudonym (XDR-3).
- Cross-domain alert normalization (XDR-2) and correlation (XDR-4).
- Entity attributes beyond aliases (risk, tier) — later increments.

## Decisions

### D1 — Aliases point to entities; the canonical pseudonym is the device alias
An `entity` is an abstract asset; `entity_aliases(kind, value)` are its names. `kind='device'` with the
canonical pseudonym, `kind='user'` with the identity. `(kind, value)` is unique — one alias belongs to
exactly one entity — so `Resolve('device', pseudonym.Of(A))` is deterministic and the SAME across
domains that all derive that pseudonym the one shared way. This is why IDENT-1 was the hard-dep: without
one derivation, the same device would key differently per domain and never coalesce.

### D2 — Atomic find-or-create via a per-alias advisory lock
Concurrent ingest can resolve the same new alias at once; a naive select-then-insert would create two
entities. `Resolve` runs in a transaction that first takes `pg_advisory_xact_lock(hashtext(kind|value))`
(the same per-key serialization VerifySigned uses, D180), then selects-or-inserts — so exactly one entity
is created for a new alias and the rest read it. The lock is per-alias, not global, so unrelated resolves
do not serialize.

### D3 — Link merges, lock-ordered to avoid deadlock
`Link(aliasA, aliasB)` ties both to one entity. In a transaction it locks both aliases in a fixed sorted
order (so two concurrent links of the same pair cannot deadlock), resolves each (creating a fresh entity
if new), and if they differ **merges**: repoint the loser entity's aliases to the winner (the
lower-id/older entity) and delete the emptied loser. Merging toward the older entity keeps the surviving
id stable. A device seen alone gets its own entity; when its user later authenticates on it, `Link`
coalesces them — no data is lost, the aliases just re-home.

### D4 — Postgres is the system of record; the store is a thin, testable seam
The entity graph is durable server state (like the ledger and fleet telemetry), so it lives in Postgres
and the store is a small `internal/xdr` type over the pool — testable directly against a real database
(the recurring discipline: prove the concurrency and the canonical join against the real substrate, not
an in-memory fake that would agree with the code).

## Risks / Trade-offs

- **Merge cost** — repointing aliases on `Link` is O(aliases of the loser); entities have few aliases, so
  it is cheap. A merge is rare (only when a device and user first co-occur).
- **No un-merge** — merging is one-way; splitting a wrongly-merged entity is a manual/later concern.
  Mitigated because links come from authenticated co-occurrence (a verified device cert + user), not a
  guess.

## Migration Plan

Additive: one migration (two tables), a new package. No proto/core/existing-store change. The
migration-count contract test bumps 20 → 21.

## Open Questions

- Whether an entity should carry a stable external UUID (vs the bigserial id) for cross-system reference.
  The bigserial is sufficient within OpenShield; a UUID is a later addition if needed.
