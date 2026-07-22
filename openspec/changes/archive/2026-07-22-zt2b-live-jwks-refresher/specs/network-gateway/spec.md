## MODIFIED Requirements

### Requirement: A signed OIDC bearer token resolves into a verified Zero-Trust identity
The gateway MUST verify a signed OIDC/JWT bearer token — its issuer, audience, expiry, and
signature — against a configured key set, and resolve a valid token into the same
pseudonymous Zero-Trust identity as a client certificate (a one-way subject and an
authorization role from a configured claim). A token that is malformed, expired, not yet
valid, signed by an unknown or wrong-type key, carries a wrong issuer or audience, uses an
unsafe algorithm, or lacks a subject or role MUST be rejected — never resolved to a partial
or defaulted identity. The signing key set MAY be sourced from a live JWKS endpoint so an
identity-provider key rotation is picked up without a restart; when it is, the gateway MUST refresh
the keys in the BACKGROUND (the token-verification path MUST NOT perform a network fetch), MUST serve
the last-good keys when a refresh fails (a provider outage MUST NOT black out verification of tokens
signed by still-valid keys), and MUST rate-limit any refresh triggered by an unknown key id (an
unknown-key-id flood MUST NOT drive unbounded fetches). An unknown key id MUST remain a rejection until
a refresh makes the key known.

#### Scenario: A valid token resolves and an adversarial token is rejected
- **WHEN** a valid OIDC token is presented
- **THEN** it resolves to a pseudonymous subject and role; and a tampered, expired, or unsafe-algorithm token is rejected

#### Scenario: A rotated key is picked up, and a provider outage serves stale
- **WHEN** the signing key set is sourced from a JWKS endpoint, the provider rotates to a new key id, and later the JWKS endpoint fails
- **THEN** a token signed by the new key verifies once a background refresh has picked it up (without a restart and without the verification path fetching), and while the endpoint is failing a token signed by a still-known key continues to verify against the last-good keys
