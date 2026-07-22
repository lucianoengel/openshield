-- Alert acknowledgement (SIEM-6).
--
-- A peer alert (D54) had no triage state — an operator seeing a stream of alerts could not
-- mark one "seen / handled / noise" without opening a full investigation case (a heavyweight,
-- four-eyes-to-close artifact). Acknowledgement is the lightweight half of the lifecycle: the
-- actionable queue is the UNACKNOWLEDGED alerts above a severity, and an ack takes an alert out
-- of it, attributed to the operator who triaged it.
--
-- acknowledged_at is nullable (NULL = not yet acknowledged, the queryable "still actionable"
-- state). acknowledged_by is the VERIFIED operator identity (from the mutual-TLS client cert,
-- never a caller-supplied name) and empty until acknowledged. First ack wins; a later ack on an
-- already-acknowledged alert is a no-op (the WHERE acknowledged_at IS NULL guard), so the
-- original triager and time are preserved.
ALTER TABLE peer_alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;
ALTER TABLE peer_alerts ADD COLUMN IF NOT EXISTS acknowledged_by TEXT NOT NULL DEFAULT '';

-- The actionable-queue query filters on the unacknowledged state; index it.
CREATE INDEX IF NOT EXISTS peer_alerts_unack_idx ON peer_alerts (acknowledged_at) WHERE acknowledged_at IS NULL;
