## MODIFIED Requirements

### Requirement: Peer-UEBA baselines survive a restart
The control plane MUST persist the peer-UEBA baseline and reload it when peer-UEBA is enabled, so a
restart or deploy does not cold-start analytics and blind the fleet to peer anomalies for a decay
window. Persistence MUST be best-effort: a failure to load a persisted baseline MUST log and start
cold rather than block enabling detection, and persistence MUST NOT break or stall ingest.
Re-persisting MUST be idempotent per subject. Persistence MUST bound its own growth by pruning
subjects whose activity has decayed below a small threshold — removing their persisted rows, not only
their in-memory state — and MUST write the pruned deletes and the surviving upserts ATOMICALLY. On
load, the control plane MUST reject a persisted row whose activity count is not finite and
non-negative or whose last-seen time is in the future (beyond a small clock-skew grace), starting that
subject cold rather than applying a corrupt baseline.

#### Scenario: A subject's baseline survives a simulated restart
- **WHEN** subjects are observed and baselines are persisted, then a fresh control-plane instance enables peer-UEBA
- **THEN** the fresh instance loads the persisted baseline so a subject's peer risk is preserved, while an instance with no persisted baseline starts cold with no baseline

#### Scenario: Decayed rows are pruned and a corrupt row is not loaded
- **WHEN** a subject's activity has decayed below the prune threshold at persist time, and separately a stored row carries a NaN/negative count or a future last-seen at load time
- **THEN** the decayed subject's row is removed on persist, and the corrupt row is skipped on load so it never enters the analyzer
