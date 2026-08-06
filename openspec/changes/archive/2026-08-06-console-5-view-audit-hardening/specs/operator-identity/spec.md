## ADDED Requirements

### Requirement: The retention window on the record of who looked MUST have a floor

The configured retention for the record of operator reads SHALL be refused below a floor, and the
refusal SHALL name what a shorter window destroys.

The record of who looked is the control that bounds an insider holding an operator role. Its retention is
an ordinary administrative setting: single tier, no second approval, no waiting period. Without a floor,
setting it to zero alongside a frequent purge interval deletes the entire accountability record —
including the rows recording the reads of whoever set it — through the product's own sanctioned delete
path, which the ledger's hash chain does not cover, and the purge then files a compliance event saying
the deletion was policy.

Recording the DIRECTION of the change is not sufficient on its own. The party the record constrains is
the party that can weaken it, and an entry noting that they did so is written into the table they are
about to purge.

#### Scenario: A window that erases the record is refused
- **WHEN** the retention window for recorded operator reads is set below the floor
- **THEN** the value is refused, and the refusal states that a shorter window destroys the
  accountability record through a delete path the ledger does not cover

#### Scenario: A short but legitimate window is still accepted
- **WHEN** an operator sets a retention window at or above the floor
- **THEN** the value is accepted, so the floor bounds the destructive end of the range rather than
  choosing the deployment's privacy policy for it
