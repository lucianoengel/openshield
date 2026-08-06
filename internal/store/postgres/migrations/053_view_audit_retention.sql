-- CONSOLE-5: the view audit says WHAT was read, and stops growing forever.
--
-- Two defects, both in migration 007, both made much worse by a console.
--
-- 1. THE RECORD DID NOT SAY WHAT WAS READ. `(viewer, subject_filter, event_id)` was enough while four
--    handlers recorded views and the shape of the arguments implied which one wrote the row. Across the
--    console's primary reads it is not: "operator X looked" does not distinguish a dashboard refresh
--    from a targeted search for one named endpoint, and that distinction is the whole of what the
--    malicious-insider boundary in docs/threat-model.md defends. `route` is the path served; `query` is
--    the canonicalised, length-bounded filter that selected the rows.
--
--    NOT FOLDED INTO subject_filter. That column means "the subject this read named" and /subject and
--    /cases write real subject ids into it — the only join that answers "who looked at me". Overloading
--    it with a route and a filter would break that join silently, which is exactly how an audit table
--    stops being one.
--
--    NOT NULL DEFAULT '' so every existing row and every existing reader keeps its meaning: a view
--    recorded before this migration has no route because none was captured, not because it was empty.
--
-- 2. THERE WAS NO TTL, NO PURGE AND NO DSAR PATH, while the table stores RAW, NON-PSEUDONYMISED operator
--    identities — attributable by design (a pseudonymised accountability record accounts to nobody).
--    Every other subject-adjacent store here is bounded: fleet_telemetry and peer_alerts under
--    OPENSHIELD_FLEET_RETENTION, the notify-dedupe ledger under its own window, each purge recorded as a
--    compliance event. This was the one that grew forever, and a console makes it the largest table in
--    the database. The index below is what the purge deletes by; OPENSHIELD_VIEW_AUDIT_RETENTION is the
--    window, and it defaults LONGER than the fleet window on purpose — an accountability record that
--    expires before the evidence it describes leaves nothing to check a disputed read against.
ALTER TABLE investigation_views ADD COLUMN IF NOT EXISTS route TEXT NOT NULL DEFAULT '';
ALTER TABLE investigation_views ADD COLUMN IF NOT EXISTS query TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS investigation_views_viewed_idx ON investigation_views (viewed_at);
