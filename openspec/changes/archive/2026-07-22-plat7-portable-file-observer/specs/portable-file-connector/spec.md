## ADDED Requirements

### Requirement: Portable file-change detection
The connector SHALL detect file creations and modifications in a watched directory using standard-library directory scanning and file metadata only, so it runs identically on linux, windows, and darwin without OS-specific privilege or syscalls.

Detection compares a snapshot of the watched directory against the previous snapshot: a path present now but absent before is a creation; a path whose size or modification time changed is a modification. Detection considers regular files only and is non-recursive (files directly in the watched directory).

#### Scenario: A newly created file is detected
- **WHEN** a regular file that was absent in the previous snapshot appears in the current snapshot
- **THEN** the connector produces one Event of kind `EVENT_KIND_FILE_CREATED` for that path

#### Scenario: A modified file is detected
- **WHEN** a file present in both snapshots has a changed size or a changed modification time
- **THEN** the connector produces one Event of kind `EVENT_KIND_FILE_MODIFIED` for that path

#### Scenario: An unchanged file produces nothing
- **WHEN** a file is present in both snapshots with identical size and modification time
- **THEN** the connector produces no Event for that path

#### Scenario: A same-size content change is still detected
- **WHEN** a file's content changes without changing its size but its modification time advances
- **THEN** the connector produces an `EVENT_KIND_FILE_MODIFIED` Event for that path

### Requirement: Silent baseline priming
The connector SHALL NOT emit creation Events for files that already exist when watching begins; the first scan establishes a baseline silently.

Without this, every pre-existing file in a watched directory would flood the pipeline with spurious creation Events at startup.

#### Scenario: Pre-existing files do not fire at startup
- **WHEN** the watched directory already contains files at the moment watching starts
- **THEN** no Event is produced for those files until they are subsequently created anew or modified

#### Scenario: A file created after startup does fire
- **WHEN** a new file appears in the watched directory after the baseline scan
- **THEN** an `EVENT_KIND_FILE_CREATED` Event is produced for it

### Requirement: Events reuse the filesystem contract
The connector SHALL emit Events carrying the existing `FilesystemSubject` target with the resolved path, and SHALL NOT introduce any new Event kind, subject type, or proto field.

The Event carries the file path as metadata only; the connector never reads or transmits file content (D29). Classification of the file happens later in the sandboxed worker, exactly as for the fanotify connector.

#### Scenario: The produced Event names the path and no content
- **WHEN** the connector produces an Event for a file change
- **THEN** the Event's `FilesystemSubject` resolved path is the watched directory joined with the file name, and the Event carries no file content

#### Scenario: Only existing enum values are used
- **WHEN** the connector classifies a change as a creation or a modification
- **THEN** it uses `EVENT_KIND_FILE_CREATED` or `EVENT_KIND_FILE_MODIFIED` and defines no new kind

### Requirement: Bounded, observe-only operation
The connector SHALL bound the number of files it tracks per scan and SHALL be observe-only, producing Events for a downstream pipeline without taking any enforcement action itself.

When a watched directory exceeds the tracked-file bound, the connector SHALL surface that loudly (a logged, counted condition) rather than silently ignoring the excess — silent truncation would misrepresent coverage.

#### Scenario: The connector never enforces
- **WHEN** the connector detects a file change
- **THEN** it emits an Event and takes no action on the file (no block, delete, quarantine, or modification)

#### Scenario: Exceeding the file bound is surfaced
- **WHEN** a watched directory holds more files than the tracked-file bound
- **THEN** the excess is reported through a loud, counted signal rather than being silently dropped

### Requirement: Interface-compatible with the engine's file watcher
The connector SHALL expose the same watcher shape the engine already consumes — an open call returning a watcher with a blocking `Next(ctx)` that yields one Event at a time and a `Close()` — so the engine selects it in place of the fanotify connector with no change to the pipeline.

`Next` blocks until the next change is available or the context is done; a scan that yields several changes is buffered and returned one Event per call.

#### Scenario: Next yields one buffered event at a time
- **WHEN** a single scan detects several changed files
- **THEN** successive `Next` calls return those Events one at a time before the watcher scans again

#### Scenario: Next returns when the context is done
- **WHEN** the watcher's context is cancelled while it is waiting for the next change
- **THEN** `Next` returns the context error rather than blocking forever

### Requirement: Cross-platform build and run
The connector SHALL compile for windows and darwin as well as linux, and its detection logic SHALL run and be proven on linux; it establishes the cross-platform observe seam.

Because the watcher is pure standard library (`os.ReadDir`/file metadata), the same code runs on Windows and macOS; validating that runtime on real Windows/macOS hardware is an external-gated follow-up.

#### Scenario: Cross-compilation succeeds
- **WHEN** the project is built with `GOOS=windows` and with `GOOS=darwin`
- **THEN** the build succeeds with the portable connector and its engine wiring included

#### Scenario: The detection logic is proven on Linux
- **WHEN** the connector's tests run on linux against a real temporary directory
- **THEN** create and modify detection, silent priming, and bounded operation are all exercised against real files
