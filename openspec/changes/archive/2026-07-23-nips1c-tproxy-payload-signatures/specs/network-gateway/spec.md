## ADDED Requirements

### Requirement: The transparent inline mode classifies the peeked payload

The transparent inline mode SHALL classify the peeked initial bytes of a redirected flow through the
sandboxed content-signature engine, so a flow whose cleartext payload matches a content signature is
dropped inline — in addition to a block by destination IP or SNI. The classification MUST run in the
sandboxed worker (the payload is attacker content), MUST be bounded to the peeked prefix, and MUST NOT
change the fail-open behavior: a worker or pipeline error MUST forward the flow. A flow with no configured
signatures, or whose peeked payload matches none, MUST be decided exactly as it would be without payload
classification.

#### Scenario: A flow whose payload trips a content signature is dropped
- **WHEN** a redirected flow's peeked cleartext payload matches a configured content signature
- **THEN** the flow is dropped inline

#### Scenario: A clean payload is spliced
- **WHEN** a redirected flow's peeked payload matches no signature
- **THEN** the flow is decided on its other metadata and, if allowed, spliced to its destination with the peeked bytes replayed

#### Scenario: A worker error forwards the flow
- **WHEN** classifying the peeked payload errors
- **THEN** the flow is forwarded to its destination (fail-open), not dropped
