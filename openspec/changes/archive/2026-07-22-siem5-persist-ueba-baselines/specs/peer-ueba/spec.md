## ADDED Requirements

### Requirement: The analyzer can snapshot and restore its baseline exactly

The peer-UEBA analyzer SHALL expose a serializable snapshot of its per-subject baseline and
SHALL be constructible from such a snapshot. Because activity decay is computed forward from
each subject's last-update time, a restored analyzer MUST compute the same peer-relative risk
for a subject as the original analyzer would at the same evaluation time — restoring is exact,
not approximate.

#### Scenario: A restored analyzer reproduces the original risk

- **WHEN** subjects are observed, the analyzer is snapshotted, and a new analyzer is constructed from that snapshot
- **THEN** the new analyzer computes the same peer-relative risk for a subject as the original
- **AND** an empty or absent snapshot yields a cold analyzer with no baseline
