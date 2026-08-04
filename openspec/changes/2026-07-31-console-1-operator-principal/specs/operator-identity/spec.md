## ADDED Requirements

### Requirement: An authenticated operator identity MUST reach every handler that attributes an act

A handler that records who acted or who viewed SHALL obtain the operator identity from the authentication
the tier gate already performed, not by re-deriving it from the transport.

Deriving it from the transport is why SSO shipped unusable: the gate accepted a bearer token and the
handler then demanded a client certificate, so an operator authenticated by the identity provider passed
authorization and was refused by the code authorization had just admitted them to. An authentication method
that reaches the queue but not the acknowledgement is not an authentication method.

A request that reaches a handler SHALL carry a principal, or the handler SHALL refuse it. A handler MUST
NOT construct an anonymous, empty or defaulted identity when the context carries none.

#### Scenario: An operator authenticated by bearer token can acknowledge an incident
- **WHEN** an operator with the responder tier presents only a verified bearer token and acknowledges an incident
- **THEN** the acknowledgement succeeds and is attributed to that operator

#### Scenario: An operator authenticated by bearer token can read a timeline
- **WHEN** an operator with the analyst tier presents only a verified bearer token and reads an incident timeline
- **THEN** the timeline is served and the view is recorded under that operator

#### Scenario: A handler with no principal on the context refuses
- **WHEN** a handler is reached with no authenticated principal on the request context
- **THEN** the request is refused and nothing is recorded

### Requirement: An operator principal MUST be namespaced by the credential that proved it

An operator principal SHALL carry the authentication method and, for a federated credential, the issuer
that asserted it. A role record SHALL be keyed by that namespaced principal.

An unnamespaced principal makes an identity-provider subject and a certificate CommonName occupy the same
key space. An administrator whose certificate names them `alice@corp.example` is then impersonable by
anyone who can obtain an identity-provider account with that subject — a guest tenant, an external
federation, or a provisioning call — and the impersonation is indistinguishable from the administrator at
the point of lookup.

A role lookup for a principal with no namespace SHALL deny. Falling back to an unnamespaced match restores
the collision.

#### Scenario: An identity-provider subject does not inherit a certificate holder's role
- **WHEN** an operator record exists for a certificate CommonName and a token presents the same string as its subject
- **THEN** the token bearer has no role and every operator route refuses them

#### Scenario: The same subject from a different issuer is a different operator
- **WHEN** a role is granted to a subject asserted by one issuer and a token presents that subject asserted by another
- **THEN** the second token bearer has no role

#### Scenario: An unnamespaced role record denies
- **WHEN** a role lookup finds a record that carries no authentication method
- **THEN** the lookup denies rather than matching it

### Requirement: Four-eyes MUST compare the human, not the credential

An approval SHALL be refused when the approver and the requester resolve to the same operator account,
regardless of which credential each of them used.

Four-eyes is enforced as a comparison in the update predicate. Two credentials belonging to one person
produce two different principal strings, so the comparison succeeds and the control passes while one human
performs both halves. This is the failure the control exists to prevent, and it appears the moment a second
credential class is accepted — not through any error by the operator.

The refusal SHALL apply to every approval-gated act, including case closure, a `CONTAIN` or `REVOKE_TRUST`
intent, and a fleet enforcement disable.

#### Scenario: One human with two credentials cannot approve their own request
- **WHEN** an operator requests an approval-gated act with one credential and approves it with another credential linked to the same account
- **THEN** the approval is refused and the request stays pending

#### Scenario: The refusal reaches the tier gate before it is asserted
- **WHEN** the self-approval attempt is made
- **THEN** the request is observed to have passed authentication and authorization before being refused on four-eyes

#### Scenario: Two distinct operators still satisfy four-eyes
- **WHEN** one operator requests an approval-gated act and a different operator approves it
- **THEN** the approval succeeds

### Requirement: A machine principal MUST NOT satisfy four-eyes

A credential issued to an automation SHALL be a distinct principal kind from a credential issued to a
person, and an approval SHALL be refused when either the requester or the approver is a machine principal.

Without a machine kind, an integration is given a human's credential, and every control that reasons about
"a different person" then reasons about a shared secret instead. Two-person control is the specific
casualty: a service account holding a second credential is exactly the second string the account comparison
exists to collapse.

A machine principal SHALL carry its own lifecycle — issue, scope, expiry, rotation, revocation — and
expiry SHALL be mandatory, because a non-expiring automation credential is the one nobody rotates.

#### Scenario: A service account cannot approve
- **WHEN** an approval is resolved by a machine principal
- **THEN** it is refused and the approval stays pending

#### Scenario: A service account cannot request an act it could then have approved
- **WHEN** a machine principal requests an approval-gated act
- **THEN** the act is refused rather than left pending for a human to approve

#### Scenario: An expired machine credential authenticates nothing
- **WHEN** a machine principal presents a credential past its expiry
- **THEN** the request is unauthenticated

### Requirement: Privilege over personal data MUST be separable from privilege over configuration

Authority over personal data SHALL be grantable independently of authority over configuration: exporting a
data subject's compiled record, releasing a legal hold, and reading the view audit are one grant, and
changing configuration is another.

Fusing them means the person who tunes a detector is, necessarily, the person who can read every
employee's compiled personal data — and an access review has no way to say otherwise. The product already
treats privacy as architecture rather than an addition; an authorization model that cannot express "this
administrator may not read subject data" contradicts that.

#### Scenario: A configuration administrator cannot export subject data
- **WHEN** an operator holding only configuration authority requests a data subject export
- **THEN** the request is refused

#### Scenario: A privacy officer cannot change configuration
- **WHEN** an operator holding only privacy authority applies a configuration change
- **THEN** the request is refused

#### Scenario: An upgraded administrator holds both and can be narrowed
- **WHEN** an administrator granted both authorities by an upgrade is re-granted configuration authority alone
- **THEN** the authority over personal data is removed from that operator

#### Scenario: Reading the view audit leaves a view record
- **WHEN** an operator holding privacy authority reads who viewed an investigation
- **THEN** the record is served and the reading is itself recorded against that operator

### Requirement: An operator route MUST be unreachable only by decision

The set of operator routes, their minimum tiers and their handlers SHALL be declared once as data, and both
the handler mux and the tier-gated mux SHALL be built from that declaration.

A route registered on the inner mux and omitted from the outer mount is served by nothing, and the omission
is invisible: the handler exists, its tests pass, and no request reaches it. The guard against this is a
hardcoded list of six paths that has not grown with the surface, which is how the response-report route
shipped unreachable.

Declaring the set once makes the omission unrepresentable rather than caught.

#### Scenario: Every declared route is served
- **WHEN** each route in the declaration is requested with a sufficient credential
- **THEN** none of them responds as unrouted

#### Scenario: Every declared route is gated
- **WHEN** each route in the declaration is requested with no credential
- **THEN** each is refused as unauthenticated

#### Scenario: The response report is reachable
- **WHEN** an operator with the analyst tier requests the response report
- **THEN** it is served

## MODIFIED Requirements

### Requirement: A view without a verified identity is refused

An investigation view MUST be refused when the request carries no verified operator identity, and the view
MUST NOT be recorded or returned.

A verified identity is established by a verified mutual-TLS client certificate **or** by a verified
federated token, and both yield a namespaced principal. The earlier form of this requirement named the
certificate specifically, because it was the only credential that existed; the property it protects is that
a recorded view has an identity to attribute it to, not that the identity arrived over TLS.

An unverifiable credential SHALL yield no identity at all — not a reduced one, and not an anonymous viewer.

#### Scenario: A request with no credential is refused
- **WHEN** an investigation view is requested with no credential
- **THEN** the request is refused and no view is recorded

#### Scenario: A request with an unverifiable token is refused
- **WHEN** an investigation view is requested with a malformed or unverifiable token
- **THEN** the request is refused and no view is recorded

#### Scenario: A view established by a verified token is recorded under that identity
- **WHEN** an investigation view is requested with a verified token
- **THEN** the view is served and recorded under that operator's namespaced principal
