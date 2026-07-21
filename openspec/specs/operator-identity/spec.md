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

