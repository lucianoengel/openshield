-- Fleet telemetry (T-023).
--
-- The control plane's AGGREGATE view of what the fleet reported. This is NOT the
-- agent's forward-secure audit ledger (audit_entries) — it has no hash chain and
-- no signatures, and a compromised control plane could alter it. The evidentiary
-- record is the agent's local ledger, externally anchored (T-019). Keeping the
-- two distinct is deliberate: the aggregate is a queryable convenience, not
-- evidence.
--
-- payload is the raw proto, so no fidelity is lost and a contract change does not
-- force a migration here. agent_id is self-asserted until identity (T-017).
CREATE TABLE IF NOT EXISTS fleet_telemetry (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    kind        TEXT NOT NULL,           -- event | classification | decision
    event_id    TEXT NOT NULL DEFAULT '',
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload     BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS fleet_telemetry_agent_idx ON fleet_telemetry (agent_id);
CREATE INDEX IF NOT EXISTS fleet_telemetry_event_idx ON fleet_telemetry (event_id);
