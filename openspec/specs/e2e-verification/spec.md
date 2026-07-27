

### Requirement: The shipped binaries are tested as real processes

Verification SHALL include tests that run the built commands as subprocesses against real infrastructure.
Package tests cannot reach the wiring in `cmd/` — which setting reaches which constructor, which loop is
started, which subscription is registered — and that wiring is where a defect survives to a deployment
because every unit involved passes alone.

#### Scenario: The binary brings up its own schema
- **WHEN** the control plane starts against a database it has never seen
- **THEN** the schema is migrated and the tables the product depends on exist

#### Scenario: Configuration validation is reached by the process
- **WHEN** a bootstrap setting is malformed
- **THEN** the binary refuses to start and names the field and the constraint

### Requirement: The suite does not depend on fixed ports or fixed names

Infrastructure started by the suite SHALL use kernel-assigned ports and per-run names. A suite that binds
fixed ports fails on any machine already running the software, which reads as a broken test rather than a
busy machine — and a test that reads as broken stops being run.

#### Scenario: The suite runs alongside a development stack
- **WHEN** the same services are already running on their conventional ports
- **THEN** the suite still runs, against its own instances

#### Scenario: A crashed run does not poison the next
- **WHEN** a previous run left containers behind
- **THEN** a new run is unaffected by them

### Requirement: A failing scenario is diagnosable

When a scenario fails, the output of every subprocess it started SHALL be reported. An integration failure
whose cause is in a discarded stderr cannot be diagnosed, and an undiagnosable suite is abandoned.

#### Scenario: Subprocess output accompanies a failure
- **WHEN** a scenario fails with a running subprocess
- **THEN** that process's output is included in the failure

### Requirement: The suite degrades rather than blocking the gate

Without a container runtime the suite SHALL skip. Verification that cannot run everywhere must not make
the ordinary gate unusable, or it will be removed from it.

#### Scenario: No container runtime available
- **WHEN** podman is not present
- **THEN** the scenarios skip and the gate stays green

### Requirement: The correlation-to-response chain is verified end to end

The path from detection alerts through correlation, incident materialization, playbook execution and its
recorded effects SHALL be verified by running the real components against real infrastructure, driven only
by inputs a deployment actually has — stored detections and stored configuration. No stage may be invoked
directly by the verification, because a chain whose stages are called individually is not a chain.

#### Scenario: A burst of alerts reaches a case without an operator
- **WHEN** alerts for one subject exceed the configured correlation threshold and a playbook is configured
- **THEN** an incident is raised, a playbook run completes, and each step's effect is recorded — with
  automated work attributed to the playbook rather than to any person

#### Scenario: Repeated correlation does not multiply response
- **WHEN** the correlation loop runs many times over the same underlying detections
- **THEN** exactly one incident, one run, one case and one of each step's effect exist

#### Scenario: A broken query is not mistaken for a pending condition
- **WHEN** a verification polls for a condition using a query that cannot succeed
- **THEN** it fails immediately naming the query, rather than waiting out its timeout and reporting the
  system under test as broken
