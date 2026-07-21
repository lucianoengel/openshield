-- Verified telemetry (T-017 over the wire).
--
-- Distinguishes telemetry verified against an enrolled agent key (attributable)
-- from the legacy unsigned path (self-asserted, D41). An aggregate that cannot
-- tell them apart would present unverified data as evidence.
ALTER TABLE fleet_telemetry ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT false;
