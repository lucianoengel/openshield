-- CONSOLE-8: the break-glass register — what was SENT, not only what agents reported back.
--
-- PLAT-9 built `agent_enforcement`, the projection of what each agent SAYS its enforcement state is. It
-- deliberately merges two causes: an agent disabled by a fleet control and an agent disabled by its own
-- local break-glass file report identically, because the control plane has no other way to learn the
-- second. That is right for the agent's state and leaves the fleet view with nothing to compare against —
-- "my disable arrived" and "seventeen hosts turned themselves off" look the same.
--
-- Meanwhile the control itself was never recorded at all. `PublishFleetControlSeq` marshals issued_at,
-- expires_at and reason onto the wire and discards all three; the only durable trace was the sequence
-- counter in config_settings and the four-eyes approval row. So "enforcement is off — since when, until
-- when, and why?" had no answer anywhere in the product.
--
-- INVARIANTS.md:131: "'How do I stop this?' is the question a CISO asks before 'what does it detect?'"
CREATE TABLE IF NOT EXISTS fleet_controls (
    control_id  TEXT PRIMARY KEY,
    verb        TEXT NOT NULL,
    -- Monotonic per control plane, and the ordering consumers use. UNIQUE because two controls at the
    -- same sequence would make "which one stands" ambiguous on the surface and on the endpoint alike.
    sequence    BIGINT NOT NULL UNIQUE,
    issued_at   TIMESTAMPTZ NOT NULL,
    -- MANDATORY, and stored as the value the fleet actually received rather than recomputed at read time:
    -- a disable with no expiry is a product that is off and nobody remembers turning off.
    expires_at  TIMESTAMPTZ NOT NULL,
    reason      TEXT NOT NULL DEFAULT ''
);

-- DELIBERATELY ABSENT: a `suppressed` boolean. Whether the fleet is suppressed RIGHT NOW is derived the
-- same way a consumer derives it (intent/fleetcontrol.go) — the highest-sequence control whose expiry has
-- not lapsed, being a disable. A stored flag would need a sweeper to end suppression when a TTL lapses,
-- and a sweeper that falls behind makes the console disagree with the fleet in the one direction that
-- matters: reporting protection as present when it is off.
--
-- ALSO DELIBERATELY ABSENT: `issued_by`. Publication runs from an operator-local command (D51) with no
-- authenticated principal in scope, so this column could only hold an identity nothing verified. The
-- identity that WAS verified is the four-eyes pair in `approvals`, keyed by (subject_kind='fleet-control',
-- subject_id=control_id) — which is what "by whom" means for an action requiring two people. Same
-- argument as migration 046: a name in an audit trail that nothing checked is worse than no column.

-- "Which control stands?" is a descending-sequence scan bounded by expiry.
CREATE INDEX IF NOT EXISTS fleet_controls_sequence_idx ON fleet_controls (sequence DESC);
