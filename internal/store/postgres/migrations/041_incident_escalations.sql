-- SOAR-9b: escalation deadlines for incidents nobody acknowledged.
--
-- Routing (SOAR-9) decided WHERE a notification goes the moment it is raised. Nothing decided what
-- happens when it goes there and no one answers — which is the failure alerting systems actually die
-- of. The page is delivered, the delivery is recorded as a success, and the incident sits open until
-- somebody notices it in a queue.
--
-- This table is the record of which rung of the ladder an incident has already climbed. It exists so
-- escalation is IDEMPOTENT ACROSS RESTARTS: the loop runs on a clock under the leader lease, and
-- without a durable record a restart (or a leader handover) would re-fire every rung of every open
-- incident at once — turning the mechanism that exists to get attention into the one that guarantees
-- the pager gets muted.
--
-- rung is the index of the ladder step, so the constraint "each step fires at most once per incident"
-- is a unique index rather than logic that has to remember to be correct.
CREATE TABLE IF NOT EXISTS incident_escalations (
    incident_id  BIGINT      NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    rung         INTEGER     NOT NULL,
    after_secs   INTEGER     NOT NULL,   -- the deadline this rung enforced, kept so a later config
                                         -- change does not rewrite the history of what was escalated
    sinks        TEXT[]      NOT NULL,   -- where it was sent, for the same reason
    escalated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (incident_id, rung)
);

-- The sweep asks "which open incidents are past a deadline and have not climbed this rung", so the
-- lookup is by incident.
CREATE INDEX IF NOT EXISTS incident_escalations_at_idx ON incident_escalations (escalated_at);
