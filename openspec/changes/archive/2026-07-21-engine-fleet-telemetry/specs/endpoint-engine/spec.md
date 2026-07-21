# endpoint-engine delta

## ADDED Requirements

### Requirement: The engine projects real detections to the control plane, opt-in
When a telemetry projector is configured, the engine MUST project each Decision — with its originating
Event — to the control plane after recording it locally, additively to the local ledger. It MUST NOT
project when no projector is configured (the default), and MUST NOT fail the request on a projection
error (the local forward-secure ledger is the system of record). The Event is projected as-is: its file
path is the file's identity needed for fleet investigation, and the subject is already pseudonymous.

#### Scenario: A detection projects its Event and Decision
- **WHEN** the engine processes a file event with a telemetry projector configured
- **THEN** it publishes the Event (retaining the filesystem path) and the Decision

#### Scenario: No projection without a projector
- **WHEN** the engine processes an event with no projector configured
- **THEN** nothing is projected and the single-host observe path is unchanged

#### Scenario: A projection failure does not fail processing
- **WHEN** the projector returns an error
- **THEN** processing still completes and the decision remains recorded locally
