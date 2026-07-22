## ADDED Requirements

### Requirement: Peer-UEBA baselines survive a restart

The control plane SHALL persist the peer-UEBA baseline and reload it when peer-UEBA is
enabled, so a restart or deploy does not cold-start analytics and blind the fleet to peer
anomalies for a decay window. Persistence MUST be best-effort: a failure to load a persisted
baseline MUST log and start cold rather than block enabling detection, and persistence MUST NOT
break or stall ingest. Re-persisting MUST be idempotent per subject.

#### Scenario: A subject's baseline survives a simulated restart

- **WHEN** subjects are observed and baselines are persisted, then a fresh control-plane instance enables peer-UEBA
- **THEN** the fresh instance loads the persisted baseline so a subject's peer risk is preserved
- **AND** an instance with no persisted baseline starts cold with no baseline

#### Scenario: A load failure does not block enabling detection

- **WHEN** loading persisted baselines fails as peer-UEBA is enabled
- **THEN** peer-UEBA still enables and starts cold
