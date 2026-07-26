-- PLAT-9: fleet enforcement state, projected from heartbeats.
--
-- D269 could PUBLISH a fleet-wide disable and could not tell whether it ARRIVED. "Did my disable reach the
-- fleet?" is the question an operator asks thirty seconds after issuing one, and best-effort pub/sub does
-- not answer it.
--
-- The acknowledgement rides the HEARTBEAT that already exists rather than a new transport — the same
-- discipline that put the response-intent id on Context.Version (D254) and read SOAR-5's observables from
-- the event that already carried them. This table is the projection, so "who is still enforcing?" is an
-- indexed query rather than a scan of heartbeat payloads.
CREATE TABLE IF NOT EXISTS agent_enforcement (
    agent_id        TEXT PRIMARY KEY,
    -- The agent's ACTUAL state, not merely what it was told: an agent disabled by its LOCAL break-glass
    -- file reports true here too, which the control plane has no other way to learn.
    disabled        BOOLEAN NOT NULL DEFAULT false,
    applied_sequence BIGINT NOT NULL DEFAULT 0,
    reported_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- "Which hosts have not caught up?" and "which are still enforcing?"
CREATE INDEX IF NOT EXISTS agent_enforcement_state_idx ON agent_enforcement (disabled, applied_sequence);
