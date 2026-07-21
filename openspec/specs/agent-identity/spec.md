# agent-identity Specification

## Purpose
Per-agent cryptographic identity: each agent has its own Ed25519 keypair (never a shared secret), enrolled via a single-use short-TTL token, signing telemetry with a monotonic sequence the control plane verifies for gaps (suppression) and replays; identity is revocable per agent. Root-on-host defeats it; mTLS is a complementary transport-layer concern.
## Requirements
### Requirement: Each agent has its own identity key, never a shared secret
Each agent MUST have its own Ed25519 keypair whose private key never leaves the host. The system
MUST NOT use a shared fleet secret.

A shared fleet secret makes one compromised agent equal to fleet compromise — the risk review
explicitly flagged (A6). Per-agent keys contain a compromise to one agent.

#### Scenario: Two agents have distinct keys
- **WHEN** two agents generate identities
- **THEN** their keys differ, and neither can produce the other's signatures
- **AND** a test asserts a signature from one does not verify under the other's key

### Requirement: Enrollment binds a key via a single-use, short-TTL token
Enrollment MUST bind an agent's public key to an agent id using a token that is single-use and
expires. The token MUST be stored only as a hash, and a second enrollment with the same token MUST
fail.

A single-use short-TTL token limits the blast radius of a leaked credential, and storing only its
hash means a leaked database does not leak usable tokens. A token is enrollment-only — not a
signing key — so it cannot impersonate an existing agent whose signatures require its private key.

#### Scenario: A token enrolls once and then is spent
- **WHEN** a valid token is used to enroll an agent
- **THEN** the identity is recorded and the token is marked used
- **AND** a second enrollment with the same token fails, as does an expired token

#### Scenario: Only the token hash is stored
- **WHEN** the enrollment token store is inspected
- **THEN** it holds a hash, not the token itself

### Requirement: Telemetry is signed and verified, and sequence gaps are detected
The agent MUST sign each telemetry envelope with its identity key and a monotonic sequence, and the
control plane MUST verify the signature against the enrolled key and detect sequence gaps. A gap
(suppressed messages) MUST be recorded, not silently accepted; a replay or reorder MUST be
rejected.

Telemetry is evidentiary, so it carries the audit log's bar: a trail that cannot reveal suppression
is not evidentiary. The sequence makes a dropped message between agent and control plane detectable
— the next accepted message's number reveals the hole.

#### Scenario: A valid signed message in order is accepted
- **WHEN** a correctly signed message with the next sequence arrives
- **THEN** it verifies and the last-sequence advances

#### Scenario: A gap is recorded; a replay is rejected
- **WHEN** a message arrives with a sequence beyond the next expected
- **THEN** it is accepted but the gap is recorded
- **WHEN** a message arrives with a sequence at or below the last seen
- **THEN** it is rejected as a replay/reorder
- **AND** tests assert both, and that a wrong signature is rejected

### Requirement: Identity is revocable per agent
The control plane MUST be able to revoke an agent, after which that agent's signed telemetry is
rejected, without affecting other agents.

Containing a compromised endpoint must not require disturbing the fleet. Per-agent revocation is
what makes "one agent is not the fleet" operational, not just architectural.

#### Scenario: A revoked agent's telemetry is rejected
- **WHEN** an agent is revoked and then submits validly-signed telemetry
- **THEN** verification rejects it
- **AND** another agent's telemetry still verifies

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

