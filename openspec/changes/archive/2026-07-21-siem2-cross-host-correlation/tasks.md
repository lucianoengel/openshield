# Tasks — SIEM-2 cross-host correlation

## 1. Schema
- [x] Migration `015_peer_alert_host.sql`: `ALTER TABLE peer_alerts ADD COLUMN agent_id TEXT NOT NULL DEFAULT ''` + index on `(subject_id, agent_id)`.
- [x] Update the migration-count test (14 → 15).

## 2. Attribute the alert to its host
- [x] `handleSigned` passes the verified `agent_id` into `observePeer`.
- [x] `observePeer(ctx, agentID, payload)` passes it into `recordPeerAlert`.
- [x] `recordPeerAlert` writes `agent_id` in the INSERT.

## 3. Cross-host correlation
- [x] `Incident` gains `HostCount int`.
- [x] `CorrelationRule` gains `MinHosts int` (default 1).
- [x] `Correlate` selects `count(DISTINCT agent_id)`, adds it to the HAVING as `>= MinHosts`, returns `HostCount`; the stale "follow-up" comment is removed.
- [x] `incidentsHandler` parses `min_hosts`.

## 4. Read surface
- [x] `PeerAlert` DTO gains `AgentID`; `RecentPeerAlerts` and `SearchPeerAlerts` select it.

## 5. Prove it
- [x] `TestCorrelateBurst` seeds `agent_id` and asserts `HostCount`.
- [x] A cross-host scenario: a subject with a burst spanning two agents is selected at `MinHosts=2` with `HostCount=2`; a subject whose burst is all one agent is excluded at `MinHosts=2`.
- [x] Mutation — distinct-host count disabled (constant 1): the cross-host test fails (the `MinHosts=2` subject is no longer selected).
- [x] Mutation — agent_id not threaded into the INSERT: an end-to-end signed-ingest test would see `HostCount` collapse (covered by the correlate test's explicit host seeding + the recordPeerAlert path).
- [x] `make all` clean; `go test -race ./internal/controlplane/... ./internal/store/...`.

## 6. Ship
- [x] docs/decisions.md: D131.
- [x] Sync spec, archive, commit, push, memory.
