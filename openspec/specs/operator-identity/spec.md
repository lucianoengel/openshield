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

### Requirement: An operator's authorization MUST be changeable without reissuing their certificate

The role in force for an operator SHALL be resolved server-side per request, not read from the credential
they present. A grant, a demotion or a revocation SHALL take effect on that operator's next request.

The role used to be stamped into the client certificate's Subject OU and read from there, so authorization
was frozen for the certificate's lifetime: a demotion did not apply until it expired, and there was no
primitive for removing an operator's access at all. For a product whose thesis is that every security
decision is explainable and auditable, an authorization change on a certificate-lifetime delay is a hole —
and one an incident review finds the hard way, because the operator whose access "was removed" still had it.

The certificate continues to AUTHENTICATE. It says who; the server says what they may do, now.

#### Scenario: A demotion applies to the certificate already held
- **WHEN** an operator's role is lowered while they continue to present the same certificate
- **THEN** the routes above their new tier are refused, and the routes at or below it still work

#### Scenario: Revocation beats the certificate
- **WHEN** an operator is revoked while holding a certificate that names a higher role
- **THEN** every operator route refuses them

### Requirement: Revocation MUST be recorded, not expressed as an absence

A revoked operator SHALL be stored as an explicit revoked state. Removing the record SHALL NOT be the way
revocation is expressed.

An absent record falls back to the certificate's embedded role, so implementing revocation as a deletion
would silently RESTORE whatever the certificate said — the exact inverse of the intent, and an inversion
nobody notices until it matters.

#### Scenario: A revocation leaves a record
- **WHEN** an operator is revoked
- **THEN** a revoked record exists for that identity

### Requirement: A failure to resolve a role MUST deny, never fall back

When the authorization store cannot be consulted, the request SHALL be refused. It SHALL NOT fall back to
the role in the certificate.

Falling back would turn a database outage into a silent restoration of stale privileges — a fail-open on
authorization, which is the one place this product does not fail open.

#### Scenario: The store is unavailable
- **WHEN** the role cannot be read
- **THEN** the request is refused rather than authorized from the certificate

### Requirement: The migration away from certificate-embedded roles MUST be explicit and finishable

An identity with no record MAY fall back to its certificate's role, and doing so SHALL be reported. A
deployment SHALL be able to turn that fallback off once every operator has a record.

Switching to store-only authorization in one step would lock every existing deployment out of its own
control plane, including the administrator who would have to fix it. But a fallback that is never
announced and never removable is the original defect with extra steps, so it is logged with the command
that fixes it and there is a setting that refuses it outright.

#### Scenario: A legacy operator is reported
- **WHEN** an operator is authorized from a role that exists only in their certificate
- **THEN** the server reports it, naming the command that records the role server-side

#### Scenario: Strict mode refuses a certificate-embedded role
- **WHEN** strict mode is enabled and an identity has no record
- **THEN** the request is refused regardless of what the certificate claims

### Requirement: A fleet credential MUST NOT be grantable operator authority

The operator role set SHALL be closed to the operator tiers. An agent role SHALL NOT be assignable as an
operator role.

An agent certificate is issued to every endpoint in the fleet. If one could be granted an operator tier,
compromising any single endpoint would be compromising the console.

#### Scenario: An agent role is refused
- **WHEN** a grant names the agent role, or any role outside the operator tiers
- **THEN** it is rejected

### Requirement: Operators MAY authenticate with an OIDC token, and it MUST NOT authorize them

An operator SHALL be able to authenticate with an OIDC bearer token as an alternative to a client
certificate. The token SHALL establish identity only; the role in force SHALL still come from the
server-side operator record.

Mapping an identity-provider group claim to a tier is the conventional shape and it reintroduces the defect
the certificate half removed, with a shorter fuse: a token issued before a demotion still asserts the old
group until it expires. The provider says who you are; this product says what you may do.

A token that does not verify SHALL yield no identity at all — not a reduced one, and not an anonymous
caller with a lower tier.

#### Scenario: A verified token with no operator record has no access
- **WHEN** an operator presents a valid token and has no record
- **THEN** the request is refused

#### Scenario: A demotion applies to a token already issued
- **WHEN** an operator's role is lowered while they continue to present the same token
- **THEN** the routes above their new tier are refused

#### Scenario: A revocation applies to a token already issued
- **WHEN** an operator is revoked while holding a valid token
- **THEN** every operator route refuses them

#### Scenario: An unverifiable token is not a weaker identity
- **WHEN** a request carries a malformed, absent or unverifiable token
- **THEN** it is unauthenticated

### Requirement: An operator identity MUST be attributable, not pseudonymised

The subject used to identify an operator SHALL be the raw identity, not a one-way pseudonym.

Pseudonymisation exists so the pipeline cannot carry who a MONITORED person is. An operator is not the
monitored population — they are staff acting on the system, and an action that cannot be attributed by name
is not evidence. "Who revoked this agent" has to have an answer.

#### Scenario: Operator actions are attributable
- **WHEN** an operator's authorization is recorded or changed
- **THEN** the identity stored is the real one, and the change records who made it

### Requirement: Single sign-on MUST be off unless deliberately configured, and MUST NOT half-start

Operator SSO SHALL be disabled by default. A partially configured provider SHALL be a startup failure
rather than a silent fallback to certificate-only authentication.

Enabling an identity provider must not happen by accident. And a deployment whose operators believe SSO is
on should not discover otherwise from a support ticket — the failure has to be at startup, where somebody
is watching.

#### Scenario: No provider configured
- **WHEN** no issuer is configured
- **THEN** bearer tokens are not considered at all

#### Scenario: A partially configured provider
- **WHEN** an issuer is set without the audience or the key source
- **THEN** startup fails and names what is missing

### Requirement: Operator authorization MUST be proven against the shipped binary

Verification SHALL exercise operator authorization end to end: the real control-plane binary, real mutual
TLS, and the role changed by the shipped command-line tool while a client keeps the same credential.

Handler-level tests prove the gate's logic and cannot prove the wiring — that the running binary reads what
the tool writes, and that a change reaches a connection already established. That gap is where operator SSO
shipped unusable.

#### Scenario: A demotion made with the CLI reaches a running server
- **WHEN** an operator's role is lowered with the command-line tool while they hold the same certificate
- **THEN** the routes above their new tier are refused without restarting either process

#### Scenario: A revocation made with the CLI reaches a running server
- **WHEN** an operator is revoked with the command-line tool
- **THEN** their existing credential opens nothing, and the listing shows the revocation as a fact

### Requirement: Enabling single sign-on MUST make a client certificate optional, not unverified

When operator SSO is enabled, the operator listener SHALL accept a connection with no client certificate,
and SHALL still verify any certificate that IS presented against the trusted authority.

Without the first, SSO is unreachable: an operator authenticating with a token has no certificate, so a
listener demanding one refuses them at the handshake before the token is read. Without the second, the
relaxation trades a working mutual-TLS gate for an open one — anyone could mint a certificate naming an
administrative role and the legacy fallback would honour it.

A deployment that has not enabled SSO SHALL keep demanding a client certificate.

#### Scenario: A token-authenticated operator can reach the listener
- **WHEN** SSO is enabled and a client presents a valid token and no certificate
- **THEN** the connection is established and the request is authorized from the operator record

#### Scenario: A certificate from an untrusted authority is still refused
- **WHEN** SSO is enabled and a client presents a certificate issued by an authority the server does not
  trust
- **THEN** the connection is refused

#### Scenario: Without SSO the listener is unchanged
- **WHEN** no identity provider is configured
- **THEN** a client certificate is required at the handshake as before
