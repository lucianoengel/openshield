## ADDED Requirements

### Requirement: A sender-constrained operator token MUST be useless without its key

When an operator's token declares a confirmation key, the request SHALL carry a proof of possession of that
key, bound to the method and URI, single-use, and within a freshness window. A token presented without a
valid proof SHALL be refused.

A plain bearer token is a password that happens to expire: whoever holds it is the operator. Binding it to a
key means capturing the token — from a log, a proxy, a browser history — is not enough.

A token that declares a confirmation key but arrives at a verifier that cannot check proofs SHALL be
refused, not honoured as a plain bearer. Honouring it would discard exactly the protection the issuer asked
for, and would do it silently.

#### Scenario: The token alone is not enough
- **WHEN** a sender-constrained token is presented with no proof
- **THEN** the request is unauthenticated

#### Scenario: A proof under another key is refused
- **WHEN** the proof's key is not the one the token was bound to
- **THEN** the request is unauthenticated

#### Scenario: A proof cannot be lifted onto another request
- **WHEN** a valid proof for one method and URI is presented with a different method or URI
- **THEN** the request is unauthenticated

#### Scenario: Binding cannot be silently discarded
- **WHEN** a sender-constrained token reaches a verifier with proof validation disabled
- **THEN** it is refused rather than treated as a bearer token

### Requirement: A deployment MUST be able to require sender-constrained operator tokens

It SHALL be possible to refuse an operator token that is NOT sender-constrained. That requirement SHALL
default to off.

Defaulting to on would lock out every deployment whose identity provider does not yet bind tokens. Leaving
it unavailable would mean a provider that stops binding — a misconfiguration, a downgrade, a migration —
silently returns every operator to a credential anyone who captures it can use.

#### Scenario: Unbound tokens are accepted by default
- **WHEN** the requirement is off and an unbound token is presented
- **THEN** it verifies as a bearer token

#### Scenario: Unbound tokens are refused when required
- **WHEN** the requirement is on and an unbound token is presented
- **THEN** the request is unauthenticated
