## ADDED Requirements

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
