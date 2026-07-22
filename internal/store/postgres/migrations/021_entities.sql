-- XDR-1: the unified entity model (device ⋈ user). An entity is an abstract asset;
-- entity_aliases are its names, keyed by the ONE canonical pseudonym derivation
-- (IDENT-1) so every domain's signals resolve to the same entity.

CREATE TABLE IF NOT EXISTS entities (
    id         BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One alias belongs to exactly one entity: (kind, value) is the primary key, so
-- resolving a device by its canonical pseudonym is deterministic and shared across
-- domains. kind is 'device' (canonical pseudonym) or 'user' (identity).
CREATE TABLE IF NOT EXISTS entity_aliases (
    entity_id  BIGINT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, value)
);

-- Merging an entity repoints its aliases by entity_id, so index it.
CREATE INDEX IF NOT EXISTS entity_aliases_entity_id_idx ON entity_aliases (entity_id);
