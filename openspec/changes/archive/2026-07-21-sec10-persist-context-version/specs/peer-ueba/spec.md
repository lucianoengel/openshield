# peer-ueba delta

## ADDED Requirements

### Requirement: The context version does not collide across restarts
The peer-UEBA context version MUST be monotonic and non-colliding across process restarts, so a
Decision's recorded context version unambiguously identifies which analytics snapshot applied.
Each startup MUST reserve a monotonic version range from durable storage so its versions sit in
a distinct range from any prior run.

#### Scenario: Two runs produce disjoint context versions
- **WHEN** peer-UEBA is enabled on two successive runs sharing the store
- **THEN** the two runs' context versions never coincide for the same activity
