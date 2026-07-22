# operator-identity Specification

## Purpose
Authenticated operator identity for privileged read surfaces: the investigation-view endpoint binds the recorded viewer to a VERIFIED mutual-TLS client certificate (`operator:<CN>`) instead of a self-asserted string, refuses any request without a verified certificate (no unattributable view, D20), and exists only under mutual TLS. This is authentication, not authorization — cert roles (operator vs agent) are a follow-up (D56).
## Requirements
### Requirement: A privileged view records the authenticated operator identity
An investigation view over the authenticated endpoint MUST record the viewer identity taken from the
VERIFIED mutual-TLS client certificate, not from a caller-supplied string, so the privacy trail
(T-013/D20) attributes each view to a held credential rather than a self-asserted name.

The recorded identity is derived from the peer certificate subject (`operator:<CN>`) and is
distinguishable from the legacy self-asserted library path, which stays marked
`unauthenticated:<os-user>`.

#### Scenario: An authenticated view is recorded under the certificate identity
- **WHEN** an operator with a CA-issued client certificate (CN "alice") views an investigation over
  the authenticated endpoint
- **THEN** the view is recorded with viewer `operator:alice`, not a caller-supplied name
- **AND** a test asserts the recorded viewer matches the certificate, not the request body

### Requirement: A view without a verified certificate is refused
The authenticated view endpoint MUST refuse a request that carries no verified client certificate and
MUST NOT record or return the investigation, preserving the rule that no unattributable view occurs
(D20).

#### Scenario: No client certificate means no view
- **WHEN** a request reaches the authenticated view endpoint without a verified client certificate
- **THEN** it is refused and no investigation_views row and no evidence are produced
- **AND** a test asserts both the refusal and the absence of a recorded view

### Requirement: The authenticated endpoint exists only under mutual TLS
The authenticated view endpoint MUST be exposed only when mutual TLS is configured, so it can never
record a view without a verified identity to attribute it to.

When TLS is not configured, the authenticated route is absent; the plaintext library view path
remains available but keeps its explicit unauthenticated marking.

#### Scenario: Without TLS the authenticated route is not served
- **WHEN** the control plane runs without mutual TLS configured
- **THEN** the authenticated view endpoint is not exposed
- **AND** any recorded view via the library path is marked unauthenticated, never as an operator

### Requirement: A verified certificate is authorized per route by its role
A mutual-TLS route MUST authorize a verified client certificate by the ROLE carried in its Subject
Organizational Unit, not merely authenticate it. Beyond the `agent` role (for enrollment), the
operator surface MUST support TIERED roles — `analyst`, `responder`, and `admin` — ordered so a higher
tier satisfies a lower requirement (`analyst` < `responder` < `admin`); the legacy `operator` role
MUST rank as `admin` so existing operator certificates keep full access. A route MUST gate on a
MINIMUM tier: the read surface (alerts, search, events, overdue, incidents, subject) requires at least
`analyst`, the mutating acknowledgements require at least `responder`, and the full investigation view
requires `admin`. A certificate whose role ranks below a route's minimum MUST be refused `403`, and an
`agent` (or unknown/absent) role MUST NOT be authorized for any operator route.

The role is read from the VERIFIED peer certificate (CA-verified by the handshake), never from the
request. This is authorization by a certificate attribute the issuing CA sets — as trustworthy as the
CA's issuance discipline (the same trust class as any PKI), and the win is that the role is CHECKED.

#### Scenario: The view endpoint requires the admin tier
- **WHEN** a client with a verified `agent`-role certificate (or any cert whose role ranks below admin, e.g. a bare `analyst`) calls the view endpoint
- **THEN** the request is refused `403 Forbidden` and no investigation is returned or recorded
- **AND** a client with a verified `admin`-role (or legacy `operator`) certificate is served

#### Scenario: Tiers are ordered — a higher tier satisfies a lower requirement
- **WHEN** an `analyst` cert reads the alert queue, a `responder` cert acknowledges an alert, and an `analyst` cert attempts to acknowledge
- **THEN** the analyst read is served, the responder acknowledgement is served, and the analyst acknowledgement is refused `403` (analyst ranks below responder), while an `admin`/legacy-`operator` cert is served on all of them

#### Scenario: The enrollment endpoint requires the agent role
- **WHEN** a client with a verified operator-tier certificate calls the enrollment endpoint
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

