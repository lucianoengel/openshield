# privacy-features (delta)

## ADDED Requirements

### Requirement: A data-subject access request compiles what is held about a subject
The control plane MUST compile, for one pseudonymous subject, a report of what the platform holds
about that subject across every subject-keyed store — the audit entries, the peer-UEBA alerts, the
investigation cases, and whether the subject is under a legal hold. A request with no subject id
MUST be refused, and a subject about whom nothing is held MUST return a well-formed empty report
rather than an error. The access surface MUST be operator-gated, and running a DSAR MUST be
recorded against the requesting operator's verified identity before the report is returned, so no
unattributable access to a subject's data occurs.

#### Scenario: A DSAR compiles a subject's records and is itself recorded
- **WHEN** an operator requests the data held about a pseudonymous subject
- **THEN** a report is returned summarizing that subject's audit entries, alerts, cases, and legal-hold status — scoped to that subject alone — the access is recorded against the operator's verified identity, and a subjectless request is refused while a subject with no records yields an empty report
