# network-gateway delta

## ADDED Requirements

### Requirement: A signed OIDC bearer token resolves into a verified Zero-Trust identity
The gateway MUST verify a signed OIDC/JWT bearer token — its issuer, audience, expiry, and
signature — against a configured key set, and resolve a valid token into the same
pseudonymous Zero-Trust identity as a client certificate (a one-way subject and an
authorization role from a configured claim). A token that is malformed, expired, not yet
valid, signed by an unknown or wrong-type key, carries a wrong issuer or audience, uses an
unsafe algorithm, or lacks a subject or role MUST be rejected — never resolved to a partial
or defaulted identity.

#### Scenario: A valid token resolves and an adversarial token is rejected
- **WHEN** a valid OIDC token is presented
- **THEN** it resolves to a pseudonymous subject and role; and a tampered, expired, or unsafe-algorithm token is rejected
