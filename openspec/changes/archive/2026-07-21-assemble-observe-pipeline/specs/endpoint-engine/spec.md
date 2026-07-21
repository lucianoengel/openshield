# endpoint-engine delta

## ADDED Requirements

### Requirement: The engine binary runs the assembled observe pipeline
The `openshield-engine` binary MUST run the observe path itself — opening the fanotify connector in
unprivileged notify mode (D52) over configured directories and processing each event through
classify → policy → decide → audit — rather than building the pipeline and idling. An engine
configured with no watch directories MUST refuse to start, so a running engine is never a silent
no-op.

Observe-only remains the default: the engine records Decisions and enforces nothing unless an
enforcer is registered (D1/D14). A classify failure is auditable, never a silent allow (D17). The
privileged permission-mode agent is not required for observe and remains deferred (D49).

#### Scenario: A file dropped in a watched directory flows to the ledger
- **WHEN** the running engine binary watches a directory and a file containing detectable PII is
  written there
- **THEN** the event is classified, evaluated, decided, and the Decision is recorded in the
  forward-secure ledger
- **AND** a BINARY-level test (building and running the actual engine + worker against real Postgres)
  asserts the ALERT entry appears — not a package-level test calling internal functions

#### Scenario: An engine with no watch directories refuses to start
- **WHEN** the engine binary is started with no watch directories configured
- **THEN** it exits with an error rather than running as a no-op that observes nothing
- **AND** a test asserts the refusal

### Requirement: The shipped binaries state their capability honestly
The shipped binaries and their docs MUST distinguish what runs from what is deferred: the observe
pipeline runs as the `openshield-engine` binary, while inline blocking / the privileged
permission-mode agent is deferred (D49). The `openshield-agent` stub MUST name itself the deferred
inline component and exit non-zero, not present as a healthy but silent service.

#### Scenario: The agent stub does not masquerade as a running service
- **WHEN** the `openshield-agent` stub is run
- **THEN** it identifies itself as the deferred privileged inline-blocking component, points to the
  engine for observe, and exits non-zero
- **AND** the README and CHANGELOG describe the observe path as running as a binary and inline
  blocking as deferred, with no wording implying the full privileged path ships today
