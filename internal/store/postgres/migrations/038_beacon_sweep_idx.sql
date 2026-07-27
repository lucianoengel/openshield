-- NIPS-6: an index for the scheduled beaconing sweep.
--
-- The sweep reads every VERIFIED event in a long window (24h by default, because a check-in rhythm is not
-- visible in an hour) and decodes each one to find network flows. Without an index that is a full scan of
-- the aggregate on every tick — affordable once, not on a schedule.
--
-- PARTIAL on the sweep's own predicate: the index only covers rows the sweep actually reads, so it stays
-- small on a fleet whose telemetry is mostly decisions and heartbeats.
--
-- What this index CANNOT do is narrow by EventKind: the kind lives inside the protobuf payload, not in a
-- column, so the sweep still decodes non-network events and discards them. Promoting it to a column would
-- be a schema change to the aggregate's hot write path for the benefit of one periodic reader — stated
-- here as a known cost rather than fixed speculatively.
CREATE INDEX IF NOT EXISTS fleet_telemetry_sweep_idx ON fleet_telemetry (received_at)
    WHERE kind = 'event' AND verified;
