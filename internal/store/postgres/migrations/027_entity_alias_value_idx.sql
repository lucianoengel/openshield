-- XDR-2 increment 2: a value-only index on entity_aliases.
--
-- The alias primary key is (kind, value), which cannot serve a lookup that knows the VALUE
-- but not the KIND — exactly what unified-alert keying needs, so a detection whose subject
-- another domain already registered under a different kind (the gateway's user identity vs
-- the endpoint's device pseudonym) lands on that SAME entity instead of forking onto a new
-- one. Without this index that lookup is a sequential scan on every alertable decision.
--
-- Index only: no table, column, constraint or data change.

CREATE INDEX IF NOT EXISTS entity_aliases_value_idx ON entity_aliases (value);
