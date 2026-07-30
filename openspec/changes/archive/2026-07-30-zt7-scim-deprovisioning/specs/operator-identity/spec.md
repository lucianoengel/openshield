## ADDED Requirements

### Requirement: An identity provider MUST be able to remove an operator's access

There SHALL be a SCIM endpoint at which an identity provider deactivates an operator, and deactivation
SHALL revoke their access immediately, on the credential they already hold.

Until this, removing an operator's authority relied on an administrator remembering to run a command.
"We remember" is not a control, and the gap between someone leaving and someone revoking is the window an
audit asks about.

Deactivation SHALL be recorded as a revocation, never as a deletion of the record — an absent record falls
back to the role in the operator's certificate, so deleting would restore the access the call exists to
remove.

The endpoint SHALL accept the deactivation shapes providers actually send: a patch naming the attribute, a
patch carrying an object, a replace, and a delete. A deprovisioning that works against one provider and
silently does nothing against another is worse than none, because it is believed.

#### Scenario: Deactivation removes access immediately
- **WHEN** the provider deactivates an operator who holds a valid credential
- **THEN** that credential opens nothing, without waiting for it to expire

#### Scenario: The provider's dialect does not matter
- **WHEN** deactivation arrives as a patch, a replace or a delete
- **THEN** access is removed in every case

### Requirement: Provisioning MUST identify without authorizing

Creating an operator through the provisioning endpoint SHALL record the identity and grant no role.

The provider says who exists; this product says what they may do. A create that granted a tier — from a
group, or a default — would put authorization back inside the credential path, which is the defect the
preceding work removed. The consequence is stated rather than hidden: this closes the LEAVER half of
joiner/mover/leaver, and the joiner half still ends with an administrator granting a tier.

#### Scenario: A provisioned user has no access
- **WHEN** the provider creates an operator and no tier has been granted
- **THEN** that operator is authorized for nothing, whatever their credential claims

### Requirement: The provisioning endpoint MUST NOT be reachable with an operator credential

The endpoint SHALL authenticate with its own credential, compared in constant time, and SHALL be absent
unless that credential is configured.

An operator credential able to reach it would let a lower tier deactivate a higher one — a privilege
escalation through a provisioning API. An endpoint that exists without a credential is an unauthenticated
route into the operator roster.

#### Scenario: An operator certificate is not a provisioning credential
- **WHEN** a request presents a valid operator certificate and no provisioning token
- **THEN** it is unauthenticated

#### Scenario: Unconfigured means absent
- **WHEN** no provisioning credential is configured
- **THEN** the endpoint does not exist
