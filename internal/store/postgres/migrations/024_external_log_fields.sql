-- Field-level hunting over external logs (SIEM-4 deepening).
--
-- external_logs (022) columnised a FIXED subset of each event (vendor/product/signature/name/severity/
-- host/message) and kept the rest in `raw` as opaque text. The parsers already produce a per-event
-- key/value map (CEF extensions, WEF EventData, CloudTrail's parsed fields); storing it structured lets
-- an analyst hunt on any parsed field ("TargetUserName=svc-backup", "sourceIPAddress=203.0.113.7") across
-- ALL sources, not just the fixed columns.
--
-- JSONB (not a column per key) because the field set is open-ended and vendor-specific. Default '{}' so
-- existing rows and non-field inserts stay valid (an old row simply has no structured fields until
-- re-ingested). The column inherits external_logs' writer-role grant (017 default privileges) — no new
-- grant. The GIN index serves containment/`->>` lookups.
ALTER TABLE external_logs ADD COLUMN IF NOT EXISTS fields JSONB NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS external_logs_fields_idx ON external_logs USING GIN (fields);
