# operator-identity delta

## ADDED Requirements

### Requirement: A verified certificate is authorized per route by its role
A mutual-TLS route MUST authorize a verified client certificate by the ROLE carried in its Subject
Organizational Unit (`agent` or `operator`), not merely authenticate it, so an agent certificate and
an operator certificate are not interchangeable across the enrollment and view surfaces.

The role is read from the VERIFIED peer certificate (CA-verified by the handshake), never from the
request. This is authorization by a certificate attribute the issuing CA sets — as trustworthy as the
CA's issuance discipline (the same trust class as any PKI), and the win is that the role is CHECKED.

#### Scenario: The view endpoint requires the operator role
- **WHEN** a client with a verified `agent`-role certificate (or any cert without the operator role)
  calls the view endpoint
- **THEN** the request is refused `403 Forbidden` and no investigation is returned or recorded
- **AND** a client with a verified `operator`-role certificate is served

#### Scenario: The enrollment endpoint requires the agent role
- **WHEN** a client with a verified `operator`-role certificate calls the enrollment endpoint
- **THEN** the request is refused `403 Forbidden` and no enrollment occurs
- **AND** a client with a verified `agent`-role certificate can enroll

### Requirement: Unauthenticated and unauthorized are distinct outcomes
A mutual-TLS route MUST distinguish a request with NO verified certificate (`401`, unauthenticated)
from a request with a verified certificate of the WRONG role (`403`, authorized denied), so the trail
separates "nobody" from "somebody not allowed here".

#### Scenario: No cert is 401, wrong role is 403
- **WHEN** a request reaches a role-gated route with no verified certificate
- **THEN** it is refused `401`
- **AND** a request with a verified certificate of the wrong role for that route is refused `403`

### Requirement: Role authorization applies only to the TLS-served routes
Role gating MUST apply only to the mutual-TLS routes; when TLS is not configured the plaintext dev
paths are unchanged and the view route still does not exist, so role authorization never blocks the
local dev loop.

#### Scenario: Plaintext dev loop is unaffected by role gating
- **WHEN** the control plane runs without mutual TLS
- **THEN** the plaintext library enroll/view paths behave exactly as before and no role is required
- **AND** the authenticated view route remains absent (D56)
