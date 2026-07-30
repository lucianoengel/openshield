## ADDED Requirements

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
