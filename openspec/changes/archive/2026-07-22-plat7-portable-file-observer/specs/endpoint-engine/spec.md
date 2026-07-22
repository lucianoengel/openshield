## MODIFIED Requirements

### Requirement: The engine binary runs the assembled observe pipeline
The `openshield-engine` binary MUST run the observe path itself — opening a file watcher over
configured directories and processing each event through classify → policy → decide → audit —
rather than building the pipeline and idling. The watcher is selected at build time per operating
system: on Linux the fanotify connector in unprivileged notify mode (D52), and on other operating
systems (windows, darwin) a portable, unprivileged user-mode watcher, so the same engine runs and
observes on every supported OS instead of exiting where fanotify is unavailable. An engine
configured with no watch directories MUST refuse to start, so a running engine is never a silent
no-op.

The per-OS selection MUST be a build-time seam that leaves the Linux observe path unchanged (still
fanotify) — the portable watcher is not compiled on Linux and fanotify is not compiled elsewhere.
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

#### Scenario: The engine opens a working watcher on a non-Linux build
- **WHEN** the engine is built for a non-Linux OS (windows or darwin) and watches a directory
- **THEN** it opens the portable user-mode watcher rather than the fanotify connector, so startup
  does not fail with an unsupported-platform error
- **AND** the Linux build continues to open the fanotify connector unchanged
