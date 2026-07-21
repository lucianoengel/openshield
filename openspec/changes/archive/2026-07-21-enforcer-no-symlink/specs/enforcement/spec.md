# enforcement delta

## ADDED Requirements

### Requirement: File enforcers do not follow a symlink at the flagged path
A file enforcer MUST NOT read or act THROUGH a symlink at the target path, and MUST refuse a target
that is not a regular file — so an attacker who swaps the flagged path for a symlink (or a special
file) in the window between classification and enforcement cannot redirect enforcement onto an
arbitrary file.

The refusal is a loud, auditable enforcement failure (D14), never a silent redirect. This closes the
final-component symlink swap; a parent-directory-component swap and an fd carried from classification
remain documented follow-ups.

#### Scenario: A target swapped for a symlink is refused
- **WHEN** the target that was a regular file at classification is a SYMLINK at enforcement time
- **THEN** the enforcer refuses (errors) rather than reading or acting on the symlink's destination
- **AND** a test replaces the target with a symlink to a secret file and asserts the enforcer neither
  reads nor encrypts/quarantines the destination

#### Scenario: A non-regular target is refused; a regular file is handled
- **WHEN** the target is a directory, fifo, or device
- **THEN** the enforcer refuses it, while a genuine regular file is encrypted/quarantined as before
- **AND** a test asserts both outcomes
