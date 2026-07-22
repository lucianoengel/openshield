# policy-evaluation (delta)

## ADDED Requirements

### Requirement: A process event's behavioral verdict is a policy input, decided observe-safe
The policy input for a process event MUST include a behavioral verdict (a score and the
LOLBin/lineage/encoded-command signals) derived from the event's exec metadata, so a policy can
decide on process behavior. The behavioral analysis MUST run on metadata only (no content), and the
POLICY — not the detector — MUST choose the action from the closed set. The shipped default policy
MUST ALERT (not terminate) on a suspicious score, and MUST NOT let the behavioral rule fire on a
non-process event.

#### Scenario: A suspicious process alerts and a benign one is allowed
- **WHEN** the default policy evaluates a process event whose behavioral score is suspicious, a benign process event, and a clean file event
- **THEN** the suspicious process is ALERTed (not terminated), the benign process and the file event are ALLOWed, and the behavioral rule does not fire on the file event
