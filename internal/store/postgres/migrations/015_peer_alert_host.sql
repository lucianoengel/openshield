-- Cross-host correlation (SIEM-2).
--
-- A peer alert (D54) is the control plane's own detection that a subject is anomalous
-- relative to its peers. Until now it recorded WHO and WHEN but not WHERE — which agent's
-- verified event triggered it. That dropped the cross-host facet: one subject anomalous on
-- several agents is a stronger, qualitatively different signal (lateral movement, a shared
-- credential) than a burst on a single host, and the aggregate could not express it.
--
-- agent_id is the SAME verified id that attributes fleet_telemetry — the id from the signed
-- envelope, checked against the enrolled key before the event was accepted — so the two
-- aggregates share one attribution key. It is NOT NULL DEFAULT '': a pre-identity or legacy
-- alert has no host, and empty is the honest representation (not a distinct host, so a set of
-- empties counts as one origin, and a genuine multi-host burst is what lifts the count above 1).
ALTER TABLE peer_alerts ADD COLUMN IF NOT EXISTS agent_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS peer_alerts_subject_host_idx ON peer_alerts (subject_id, agent_id);
