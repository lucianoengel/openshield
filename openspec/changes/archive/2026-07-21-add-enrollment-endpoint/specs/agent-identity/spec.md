## ADDED Requirements

### Requirement: An agent enrolls over the network with a single-use token
The control plane MUST expose an enrollment endpoint that an agent calls with its single-use token
and public key to register its identity. Token ISSUANCE MUST NOT be a network endpoint. Enrollment
errors MUST be generic, not revealing whether a token was unknown, expired or used.

`Enroll` was in-process only, so enrollment could not happen over the wire and the signed-telemetry
chain (D50) had no way to onboard an agent. Exposing enrollment — but NOT issuance — preserves the
single-use model: a leaked endpoint cannot mint credentials, and generic errors do not help an
attacker probe the token space.

#### Scenario: A valid token enrolls the agent over HTTP
- **WHEN** an agent POSTs its valid token, id and public key to the enrollment endpoint
- **THEN** the identity is recorded and the endpoint returns success
- **AND** a subsequent signed telemetry message from that agent verifies
- **AND** a test drives the handler and asserts enrollment and verified telemetry

#### Scenario: A spent or bad token is refused generically
- **WHEN** the endpoint is called with a used, expired or unknown token
- **THEN** it refuses with a generic error that does not distinguish the cases
- **AND** a malformed body or wrong-size key is a client error
- **AND** tests assert the generic refusal and the client errors

#### Scenario: Token issuance is not reachable over the network
- **WHEN** the enrollment surface is inspected
- **THEN** there is no network route that issues tokens
- **AND** issuance remains an operator-local action
