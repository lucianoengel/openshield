# decision-contract delta

## ADDED Requirements

### Requirement: The closed action set includes a network redirect verdict
The closed action set MUST include a REDIRECT verdict (send to a coaching/justification destination)
and it MUST be accepted by Decision validation; block-versus-reset is an enforcement MODE, not a
distinct verdict, and MUST NOT be a separate action — keeping the action vocabulary closed and small
so a compromised or mistaken policy source cannot express an open-ended action (D14).

#### Scenario: A REDIRECT decision validates; the vocabulary stays closed
- **WHEN** a policy emits a REDIRECT decision
- **THEN** validation accepts it as a member of the closed action set
- **AND** a test asserts REDIRECT validates and that no drop/reset action was added (mode, not verdict)
