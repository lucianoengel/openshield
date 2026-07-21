# control-plane delta

## ADDED Requirements

### Requirement: The control plane manages investigation cases with four-eyes closure
The control plane MUST let an operator open a case on a subject, assign it, and add
attributed notes, with every actor recorded from a verified operator certificate. Closing a
case MUST be a four-eyes action: one operator requests closure and a DIFFERENT operator
approves it; an operator MUST NOT be able to both request and approve the same closure, and
an approval without a prior request MUST be refused. A closed case MUST record both the
requester and the approver.

#### Scenario: A single operator cannot close a case alone
- **WHEN** an operator requests a case closure and then tries to approve it
- **THEN** the self-approval is refused and the case stays open, and only a different operator's approval closes it, recording both parties
