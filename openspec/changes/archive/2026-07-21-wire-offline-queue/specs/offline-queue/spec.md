# offline-queue delta

## ADDED Requirements

### Requirement: The durable spool has a production caller
The durable offline queue MUST be wired into the running agent, so the offline-capable principle (D1)
is realized rather than only unit-tested. The agent flushes the spool as connectivity allows, and a
bounded-queue overflow eviction MUST be surfaced loudly (no silent loss, D31).

#### Scenario: The fleet agent spools and flushes, and overflow is loud
- **WHEN** the fleet agent runs with a queue directory configured and the control plane is intermittently
  unreachable
- **THEN** telemetry is spooled during the outage and flushed when reachable, and an overflow eviction
  fires a high-severity log
- **AND** a test asserts the wiring flushes and that overflow is reported, not silent
