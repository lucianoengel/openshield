# SIEM-2: cross-host correlation — a peer alert records its originating host

## Why

The burst correlation rule (D65) groups a subject's peer alerts within a window into an
incident. Its own code carries the honest limitation: *"peer_alerts records the subject and
time but not the originating host, so temporal-by-subject is the correlation the current
aggregate supports; a host column would add the cross-host facet."*

The cross-host facet is the stronger signal. One subject anomalous on **several agents** is a
qualitatively different event from a burst on a single host — it is the classic
lateral-movement / shared-credential shape a SIEM exists to surface — but the aggregate could
not express it, because a peer alert did not record which agent's verified event triggered it.
The agent id is in hand at ingest (`handleSigned` verified it against the enrolled key) and was
simply dropped before the alert was written.

## What Changes

- **peer_alerts gains an `agent_id` column** (migration 015). The verified agent id from the
  signed envelope — already the attribution key for `fleet_telemetry` — now also attributes the
  server-side detection. Backfilled empty for pre-existing rows (`DEFAULT ''`).
- **The alert-write path threads the verified agent id** from `handleSigned` →
  `observePeer` → `recordPeerAlert`, so every new alert records the host that produced the
  triggering event.
- **Correlation surfaces the cross-host facet**: an `Incident` carries a `HostCount`
  (`count(DISTINCT agent_id)`), and the rule gains an optional `MinHosts` threshold so an
  operator can ask specifically for subjects anomalous across **N or more** distinct agents —
  the cross-host incident. `MinHosts` defaults to 1, so the existing burst rule is unchanged.
- **The operator read surface** (recent + search) returns the `agent_id`, so an investigator
  sees which host each alert came from.

This modifies the `control-plane` capability (the correlation requirement) and touches no core
interface — a new column and a new optional rule parameter, both additive.

## Impact

- Affected specs: `control-plane`
- Affected code: `internal/store/postgres/migrations/015_peer_alert_host.sql`,
  `internal/controlplane/{signed,correlate,operator_read}.go`, migration-count test.
- Not in scope (stated): materializing incidents into their own table with a lifecycle
  (they remain a recomputable query over the aggregate — "a queryable convenience, not
  evidence", D54); a graph/path view across hosts; correlation rules beyond burst + host-count
  (sequence rules, MITRE chaining are SIEM-7).
