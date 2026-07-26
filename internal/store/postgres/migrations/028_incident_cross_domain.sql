-- XDR-4: cross-domain incidents — an incident keyed by the XDR graph ENTITY, spanning domains.
--
-- The burst rule (018) raises an incident per SUBJECT from the single-domain peer_alerts table. XDR-4
-- adds a second rule over the multi-domain unified_alerts stream (025, filled by every domain since
-- D241), grouped by entity_id so a device⋈user asset correlates as one thing. Both rules coexist:
-- they answer different questions and neither replaces the other.
--
-- Additive columns only; existing rows keep kind='ueba_burst', entity_id NULL, domain_count 0 — which
-- is exactly what they are. No backfill: inventing an entity for a historic subject-keyed incident
-- would be fabricating correlation that never ran.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS kind         TEXT NOT NULL DEFAULT 'ueba_burst';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS entity_id    BIGINT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS domain_count INTEGER NOT NULL DEFAULT 0;

-- The index reshape is MANDATORY, not cosmetic. 018's incidents_open_subject_idx enforces one open
-- incident per subject REGARDLESS of kind, and a cross-domain incident also carries a representative
-- subject_id for display. Left as-is, a burst incident and a cross-domain incident for the same asset
-- would collide and the second upsert would silently overwrite the first — an operator would lose an
-- incident with no trace. Scoping by kind is what lets the two rules coexist.
DROP INDEX IF EXISTS incidents_open_subject_idx;
CREATE UNIQUE INDEX IF NOT EXISTS incidents_open_kind_subject_idx
    ON incidents (kind, subject_id) WHERE state = 'open';

-- At most one OPEN cross-domain incident per entity — the cross-domain upsert's conflict target. The
-- predicate includes kind so the index covers only cross-domain rows (burst rows have a NULL entity_id
-- and must not be constrained by it).
CREATE UNIQUE INDEX IF NOT EXISTS incidents_open_entity_idx
    ON incidents (entity_id) WHERE state = 'open' AND kind = 'cross_domain';
