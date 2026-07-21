# fanotify-connector Specification

## Purpose
The observe front-end: watches directories in fanotify NOTIFY mode and turns real file activity into path-only Events (watchedDir/name, no privileged handle resolution) — proven unprivileged from a real file change through the engine to a verifiable audit row. Blocking (permission mode) and FID resolution are the privileged edge, probed unavailable in rootless podman.
## Requirements
### Requirement: The connector turns real file activity into events, unprivileged
The connector MUST watch a directory in fanotify NOTIFY mode and produce FILE_MODIFIED/CREATED
events whose resolved path is the changed file, WITHOUT requiring privilege for the per-directory
case. Event parsing MUST be a pure function tested against the byte layout.

Notify mode with per-directory marks is what makes the observe front-end runnable without the
init-namespace CAP_SYS_ADMIN that permission mode needs (probed) — the path is the watched
directory joined with the event's name, so no privileged handle resolution is required.

#### Scenario: A real file change produces an event with its path
- **WHEN** a file is created or modified in a watched directory
- **THEN** the connector produces an event whose resolved path is that file
- **AND** a live test writes a file and asserts the event and path, running unprivileged

#### Scenario: Event parsing is verified against the byte layout
- **WHEN** a fanotify event buffer is parsed
- **THEN** the mask and filename are extracted correctly
- **AND** a unit test over a fixed layout asserts it, independent of a live kernel

### Requirement: A real file change drives the pipeline to an audit row
A file change observed by the connector MUST be able to flow through the engine to a verifiable
audit entry, unprivileged.

This is the kernel-event → audit run the walking skeleton fed synthetically; with the real
connector it runs from an actual file change, closing the observe front-end end to end.

#### Scenario: A seeded file change lands a verifiable audit row
- **WHEN** a file containing a seeded CPF is written to a watched directory and its connector event
  is processed by the engine (real worker + Postgres)
- **THEN** the decision is recorded and the ledger verifies
- **AND** a test drives this unprivileged, end to end

### Requirement: The privileged limits are recorded from measurement
Documentation MUST state that permission mode (blocking) and FID handle resolution require privilege
unavailable in rootless podman (probed), and that the connector handles the unprivileged
per-directory observe case.

Overclaiming what runs unprivileged is the failure mode; the honest boundary is measured, not
assumed. Blocking and recursive/FID watches are the privileged edge.

#### Scenario: The privilege boundary is documented
- **WHEN** the connector's limits are read
- **THEN** they state permission mode needs init-ns CAP_SYS_ADMIN and FID resolution needs
  CAP_DAC_READ_SEARCH (both probed unavailable), and the per-directory observe path works unprivileged

