# packaging

## ADDED Requirements

### Requirement: The release version is stamped into a symbol that exists

The release build SHALL inject its version into a variable that is present in the source tree, and a test
SHALL assert that the injected symbol resolves.

The linker silently ignores an injection target that does not exist — it is neither a warning nor an
error — so a release built against a missing symbol succeeds, produces artifacts, records a version in
its manifest, and ships binaries that know nothing. Nothing observable fails.

#### Scenario: An injection target that does not exist is refused
- **WHEN** the release build names a version symbol absent from the tree
- **THEN** a test fails rather than the release succeeding with unstamped binaries

#### Scenario: The version is injected in one place
- **WHEN** a new command is added to the release
- **THEN** it carries the release version without declaring anything of its own
