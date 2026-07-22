# control-plane delta

## ADDED Requirements

### Requirement: Opening a case places a legal hold on the subject's evidence
Opening an investigation case MUST place an active legal hold on the case's subject in the same
transaction as the case, so the subject's evidence cannot be purged while the investigation is
open. The hold MUST be queryable, idempotent for repeated cases on the same subject, and
releasable — with release recorded rather than deleted so the hold history stays auditable.

#### Scenario: A case holds its subject's evidence
- **WHEN** a case is opened on a subject
- **THEN** the subject is under an active legal hold, a second case on the same subject does not error, and releasing the hold ends it
