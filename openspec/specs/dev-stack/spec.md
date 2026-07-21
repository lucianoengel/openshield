# dev-stack Specification

## Purpose
The one-command dev backend: podman-compose brings up Postgres + NATS + the control plane from a clean checkout, self-migrating on boot, explicitly a dev stack (default credentials, no TLS) and not production.
## Requirements
### Requirement: One command brings up the backend stack
`podman compose up` from a clean checkout MUST bring up Postgres, NATS and the control plane, with
no manual migration or setup step. The server MUST wait for Postgres to be healthy before starting.

The plan's own verification opens with `podman compose up`; a contributor needs a running stack in
one command, or the friction of hand-wiring Postgres, NATS and migrations kills the self-hostable
promise. Self-migrating on boot removes the step most likely to be forgotten.

#### Scenario: A clean checkout yields a running stack
- **WHEN** `podman compose up` runs from a fresh clone
- **THEN** Postgres, NATS and the control plane come up, the server connects and stays running, and
  no manual migration step was required
- **AND** a documented smoke test confirms the server logs that it is subscribing to telemetry

### Requirement: The dev stack is not represented as production
The compose stack MUST be documented as a DEV stack — default credentials, no TLS, no production
tuning — and MUST NOT be presented as production-ready.

Shipping a compose file with `dev`-password Postgres and no TLS as if it were deployable is exactly
the overclaim the project forbids. A contributor must not mistake the one-command dev convenience
for a hardened deployment.

#### Scenario: The dev-only nature is stated on the surface
- **WHEN** the compose file and its docs are read
- **THEN** they state it is a dev stack with default credentials and no TLS, not production-ready
- **AND** production hardening is pointed to packaging (T-027), not implied to exist here

