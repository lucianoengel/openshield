-- External third-party logs (SIEM-4): CEF-over-syslog from the estate's firewalls / IDS / WAFs /
-- endpoint tools, parsed (D202) and persisted so OpenShield ingests the estate, not only its own
-- signed telemetry.
--
-- This is a SEPARATE table from fleet_telemetry ON PURPOSE: fleet_telemetry holds ATTRIBUTABLE,
-- signature-VERIFIED agent telemetry (a `verified` boolean, a known agent_id); external logs are
-- UNVERIFIED third-party events over unauthenticated syslog, so they must never be confused with
-- verified telemetry. source_host is the sender AS REPORTED (a hunting aid, not an attestation).
--
-- The structured CEF header fields are columns (queryable); the extension key=value map is open-ended,
-- so it is preserved in `raw` (the original line) for follow-on field-level hunting rather than exploded
-- into columns now. received_at is when WE received it (source clocks are untrusted).
--
-- The table is created by the OWNER; migration 017's ALTER DEFAULT PRIVILEGES auto-grants the non-owner
-- openshield_writer role SELECT/INSERT/UPDATE/DELETE, so no explicit grant is needed here (like 019).
CREATE TABLE IF NOT EXISTS external_logs (
    id           BIGSERIAL PRIMARY KEY,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_host  TEXT NOT NULL DEFAULT '',
    vendor       TEXT NOT NULL DEFAULT '',
    product      TEXT NOT NULL DEFAULT '',
    signature_id TEXT NOT NULL DEFAULT '',
    name         TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT '',
    message      TEXT NOT NULL DEFAULT '',
    raw          TEXT NOT NULL DEFAULT ''
);

-- Search is time-windowed and newest-first, commonly narrowed by vendor/product/host.
CREATE INDEX IF NOT EXISTS external_logs_received_idx ON external_logs (received_at DESC);
CREATE INDEX IF NOT EXISTS external_logs_vendor_idx ON external_logs (vendor, received_at DESC);
CREATE INDEX IF NOT EXISTS external_logs_host_idx ON external_logs (source_host, received_at DESC);
