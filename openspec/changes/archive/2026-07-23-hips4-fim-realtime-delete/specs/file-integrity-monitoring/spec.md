## ADDED Requirements

### Requirement: A deletion of a critical file is detected in real time

The real-time file-integrity watch SHALL trigger an immediate baseline re-check when a watched file is
deleted (or moved out of a watched directory), so a deletion is detected in real time rather than only by
the periodic poll. The fanotify event is only a trigger — the deletion is confirmed by the cryptographic
baseline re-scan, which reports the missing file as a deletion and emits it as a file-deleted event through
the pipeline. The poll remains the completeness backstop.

#### Scenario: A deleted critical file is caught in real time
- **WHEN** a file in a watched directory is deleted
- **THEN** the watch triggers an immediate re-scan that reports the deletion and emits a file-deleted event, without waiting for the next poll

#### Scenario: A file moved out of a watched directory is treated as a deletion
- **WHEN** a watched file is renamed out of its watched directory
- **THEN** the re-scan reports it as no longer present and emits a file-deleted event
