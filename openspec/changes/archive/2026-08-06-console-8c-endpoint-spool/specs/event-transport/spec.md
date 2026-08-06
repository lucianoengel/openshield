# event-transport

## ADDED Requirements

### Requirement: The endpoint that produces detections can spool them across an outage

The binary that runs the endpoint pipeline SHALL be able to hold telemetry produced while the broker is
unreachable and re-send it in order on reconnect. A simulator holding it SHALL NOT be treated as
satisfying this.

Until this, only the fleet simulator attached a spool, so a real endpoint discarded its telemetry for the
whole of any outage. The endpoint's own ledger still held every decision, so evidence survived; the
fleet's view of that host did not, and nothing in the product could reconstruct it.

#### Scenario: Telemetry produced during an outage is held and later stored
- **WHEN** the broker becomes unreachable and the endpoint produces detections
- **THEN** those records are held durably, and after the broker returns they are stored by the control
  plane

#### Scenario: Draining does not depend on the liveness signal
- **WHEN** the heartbeat is disabled
- **THEN** the spool still drains

### Requirement: An endpoint with no spool states what that costs

An endpoint configured without a spool SHALL report at startup that its telemetry is discarded while the
broker is unreachable, and that its local evidence is unaffected.

Declining the spool is a legitimate deployment choice; discovering that choice's consequence during an
incident is not.

#### Scenario: The absence is announced with its consequence
- **WHEN** an endpoint starts with no spool configured
- **THEN** it reports that telemetry will be dropped, not merely that a setting is unset
