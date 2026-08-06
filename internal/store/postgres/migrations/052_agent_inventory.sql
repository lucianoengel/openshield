-- CONSOLE-8 increment 2: what is actually running out there.
--
-- The roster could name every enrolled agent and say nothing about any of them — not its platform, not
-- its version, not whether its offline spool was quietly filling up. None of it was collected: the
-- heartbeat carried liveness and the enforcement acknowledgement and nothing describing the agent.
--
-- IN THIS TABLE RATHER THAN A NEW ONE, because all of it is projected from the SAME heartbeat at the
-- SAME instant. A separate `agent_inventory` would invent a skew state that cannot occur in reality and
-- would make the roster join two projections that can each go independently stale for no reason. One
-- upsert, one reported_at, no possible disagreement.
--
-- The table keeps its name. It is read by a shipped metrics query and by the D473 roster join, and
-- renaming it to `agent_self_report` would buy a better noun and nothing else — so this comment says
-- what it now means instead: THE AGENT'S OWN REPORT ABOUT ITSELF, enforcement state and identity alike.
--
-- NULLABLE WITH NO DEFAULT, deliberately. An agent running an older build reports none of these, and
-- '' / 0 would be a claim: "" reads as a version we could not determine, and a zero spool depth reads as
-- an empty queue. A column that has never been written must be distinguishable from one written with a
-- benign value — the same rule migration 046 applies to `assurance`.
ALTER TABLE agent_enforcement ADD COLUMN IF NOT EXISTS platform      TEXT;
ALTER TABLE agent_enforcement ADD COLUMN IF NOT EXISTS agent_version TEXT;
ALTER TABLE agent_enforcement ADD COLUMN IF NOT EXISTS spool_depth   BIGINT;

-- "Which hosts are not on the current release?" is the question a fleet inventory exists to answer, and
-- it is asked across the whole fleet rather than per agent.
CREATE INDEX IF NOT EXISTS agent_enforcement_version_idx ON agent_enforcement (agent_version);
