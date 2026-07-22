# network-gateway (delta)

## ADDED Requirements

### Requirement: The access proxy can resolve identity from a verified OIDC token
The access proxy MUST support resolving the request's user identity from a verified OIDC/JWT bearer
token when an OIDC verifier is configured, using the token's subject and role for authorization and
layering it on the required mutual-TLS device certificate. A request without a token MUST be refused,
a token that fails verification MUST be refused, and the proxy MUST fail closed on any identity
error. Without a configured verifier, the client certificate MUST remain the identity.

#### Scenario: A valid token authorizes and an invalid one is refused
- **WHEN** the access proxy has an OIDC verifier configured and receives a request with a valid token, no token, and an invalid token
- **THEN** the valid token's identity is authorized through the policy and reaches the service, the missing token is refused with 401, and the invalid token is refused with 403 without reaching the service
