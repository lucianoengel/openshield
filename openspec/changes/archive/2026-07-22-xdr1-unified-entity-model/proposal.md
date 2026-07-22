## Why

Detection breadth now spans endpoint, network, and identity — but correlation is single-domain: each
domain keys its detections by its own subject, and nothing ties a device's exec event, its DNS query,
and its user's login anomaly to *one asset*. Real XDR needs a unified entity graph (device ⋈ user) so
every domain's signals resolve to the same entity. IDENT-1 (D170) gave the fleet ONE canonical pseudonym
derivation shared across enrollment, posture, and the gateway; XDR-1 builds the entity model on top of
it, so signals that already share that pseudonym resolve to one entity id — the foundation the whole XDR
lane (normalization → correlation → coordinated response) sits on.

## What Changes

- An `entities` store (Postgres): an `entities` table and an `entity_aliases` table mapping a
  `(kind, value)` — `device`/canonical-pseudonym or `user`/identity — to an entity id.
- `Resolve(kind, value)` — find-or-create the entity for an alias, atomically (concurrent resolves of
  the same alias yield ONE entity), so the same canonical pseudonym always resolves to the same entity
  across domains.
- `Link(aliasA, aliasB)` — tie a device alias and a user alias to the same entity (device ⋈ user),
  merging their entities if they were separate.

## Capabilities

### New Capabilities
- `entity-model`: a durable device ⋈ user entity graph keyed by the canonical pseudonym, so every
  domain's detections resolve to one entity — the correlation foundation for XDR.

### Modified Capabilities
<!-- none -->

## Impact

- **Code:** migration `021_entities.sql`; a new `internal/xdr` store (`Resolve`, `Link`) over the
  connection pool, with per-alias advisory locking for atomic find-or-create and merge. Proven against
  REAL Postgres: the same alias resolves to one entity under concurrency; an exec event's device
  pseudonym and a gateway request's device pseudonym (the SAME `pseudonym.Of(agentID)`, not a test
  literal) resolve to the same entity; linking a device and a user merges their entities.
- **Scope note (honest):** this is the entity STORE and its resolution/linking. **Stamping endpoint
  events with the canonical pseudonym so ingest populates it** is XDR-3; **cross-domain alert
  normalization into the unified table** is XDR-2 (after ADR-10/SIEM-6b); **correlation rules** are
  XDR-4. This increment stands up the entity graph and proves the canonical-derivation join is real, not
  test-seeded.
