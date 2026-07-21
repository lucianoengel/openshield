## Why

The client-cert identity producer (D86) fills the Zero-Trust identity contract (D85) for
deployments that issue a client certificate per user. But many environments federate
HUMAN identity through an SSO/OIDC provider (Okta, Entra, Keycloak) instead. This adds
the SECOND identity producer — an OIDC/JWT verifier that resolves a signed bearer token
into the same pseudonymous Identity, so a token-federated deployment gets verified
identity without minting a client cert per user. This is Phase A.2b, completing Phase A's
identity-producer story (cert OR token).

## What Changes

- `identity.OIDCVerifier` (+ `NewOIDCVerifier`, `WithClock`): offline JWT validation
  against a STATIC key set — issuer, audience, expiry/not-before, and signature (RS256
  and EdDSA) — resolving a valid token into an `identity.Identity` (pseudonymous subject
  D23, role from a configured claim). Every check is fail-closed; `none`/HMAC/alg-
  confusion are rejected.

## Capabilities

### Modified Capabilities
- `network-gateway`: a second identity producer — a signed OIDC/JWT bearer token resolves
  into the same Zero-Trust Identity as a client certificate.

## Impact

- New `internal/gateway/identity/oidc.go`; `docs/decisions.md` D93.
- Proven with real signed JWTs (EdDSA + RS256): a valid token → pseudonymous subject +
  role; a tampered/expired/not-yet-valid/wrong-issuer/wrong-audience/unknown-kid/missing-
  role/empty-subject/`none`-alg/algorithm-confusion token is REJECTED.
- NOT in scope (stated): composing a user TOKEN with a device CERT (BeyondCorp's two
  credentials — user from token, device+posture from cert) is the access-proxy wiring
  follow-up, an owner design choice, staged after this producer exactly as D86 preceded
  D87; live OIDC discovery + JWKS rotation over HTTP (the gateway is the master
  chokepoint D74 — an outbound fetch on the auth path is a conscious addition, not a
  default; the operator configures the trusted keys). Respects D23 (pseudonymous
  subject), D85 (identity contract), D58 (role is verified, not inferred).
