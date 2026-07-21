## ADDED Requirements

### Requirement: A container e2e proves the server binary persists real telemetry
There MUST be an end-to-end test that drives the RUNNING containerised control-plane binary:
telemetry published over a real NATS container MUST be shown to land in a real Postgres container.
It MUST fail loudly (a bounded poll, not a fixed sleep) if the telemetry does not land.

In-process tests prove the Server struct; they do not prove the built binary, its container config,
its DSN, or the real NATS wire. Those are exactly where container bugs hide, and the compose smoke
test only proved the stack comes up — not that telemetry crosses it.

#### Scenario: Published telemetry lands in the containerised store
- **WHEN** the stack is up and an Event, ClassificationSummary and Decision are published over the
  exposed NATS
- **THEN** all three appear in the containerised Postgres `fleet_telemetry`, keyed by event
- **AND** the test polls with a deadline and fails if they do not land

### Requirement: The e2e is one idempotent, self-restoring command
Running the e2e MUST be a single command that brings the stack up, runs the test, and tears it down
— restoring the dev Postgres the unit tests use — regardless of pass or fail.

A multi-step manual e2e is one that rots and stops being run. One script that leaves the machine as
it found it, every time, is what keeps the e2e usable.

#### Scenario: The script cleans up on success and on failure
- **WHEN** the e2e script runs and the test passes OR fails
- **THEN** the stack is torn down and the dev Postgres is restored
- **AND** the script's exit code reflects the test result
