# inline-prevention delta

## MODIFIED Requirements

### Requirement: A two-tier prefilter answers the permission window, inline-blocking only high-confidence hits
The synchronous prefilter MUST submit the full-file classification job to the asynchronous
tier on every event, so inline prevention never replaces the complete classification, the
durable audit record, or containment. It MUST answer with an inline block ONLY when a
cheap, bounded partial decision is a deny AND its confidence is at least a configured floor;
a lower-confidence partial deny MUST allow the open and rely on asynchronous containment. A
failure to produce a partial decision MUST fail open, surfacing the error so it is audited,
never blocking the open. The prefilter MUST NOT parse content itself. The partial decision
MUST come from a BOUNDED prefix of the target classified in the sandboxed worker and the
same policy the asynchronous tier runs, and MUST NOT write an audit record. The prefix read
MUST use a no-follow, regular-file-only open, refusing a symlinked or special-file target.

#### Scenario: A high-confidence partial deny blocks inline while a low-confidence one does not
- **WHEN** the prefilter evaluates a permission event
- **THEN** a high-confidence partial deny yields an inline block, a low-confidence deny or a decide error allows the open, and the full-file job is submitted asynchronously in every case

#### Scenario: A bounded prefix decides synchronously without auditing
- **WHEN** the decider classifies a permission event's target
- **THEN** it reads only a bounded prefix via a no-follow regular-file open, refuses a symlinked target, parses it in the worker, decides via the policy, and returns the decision without writing the ledger
