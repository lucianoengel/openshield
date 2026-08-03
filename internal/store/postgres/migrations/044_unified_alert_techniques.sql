-- MITRE ATT&CK techniques on the unified alert stream (XDR-4b).
--
-- XDR-4 shipped cross-domain correlation whose sequence vocabulary was DOMAINS — `dlp → hips → nips`,
-- a statement about which detection plane fired rather than about what the adversary did. The
-- platform already derived technique ids (SIEM-7) and handed them to Rego as policy input, then
-- discarded them: nothing downstream of the Decision ever saw them again. This column is where the
-- derivation lands so a correlation rule can read what the endpoint evidenced instead of re-deriving
-- it from an event the control plane does not hold.
--
-- Additive and nullable. An alert written before this migration, and a server-side derivation
-- (peer-UEBA) that has no originating decision, both carry NULL — which reads as "no technique was
-- derived", the same as an empty list. There is no backfill: inventing techniques for historical
-- alerts would attribute a claim to evidence nobody examined.
--
-- TEXT[] rather than a join table: the ids are a closed curated vocabulary (internal/attack), the
-- cardinality per alert is a handful, and the only query shape is "which techniques did this entity's
-- alerts carry, in detection order" — which is an aggregation over the alert rows, not a lookup.
ALTER TABLE unified_alerts ADD COLUMN IF NOT EXISTS techniques TEXT[];

-- Hunting by technique ("show me every asset that evidenced T1567.002 this week") is a containment
-- query over the array, which is what GIN indexes.
CREATE INDEX IF NOT EXISTS unified_alerts_techniques_idx ON unified_alerts USING GIN (techniques);
