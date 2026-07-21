## Context

D86 built the client-cert identity producer. OIDC is the alternative for deployments that
federate human identity through an SSO provider. It fills the SAME D85 identity contract,
mirroring FromClientCert but reading a signed JWT instead of a verified cert.

## Goals / Non-Goals

**Goals:** resolve a signed OIDC/JWT bearer token into the pseudonymous Zero-Trust
Identity, fail-closed on every validation failure.

**Non-Goals:** composing token (user) with cert (device) in the access proxy; live
discovery/JWKS rotation; refresh flows / PKCE (a client concern, not the gateway's).

## Decisions

**Offline validation against a STATIC key set — not live discovery.** The gateway is the
master chokepoint (D74); an outbound HTTP fetch to a provider's JWKS on the authentication
path adds a runtime dependency and a fetch-time attack surface to the most sensitive node.
The operator configures the trusted keys (kid → RSA/Ed25519 public key). Live discovery is
a conscious follow-up, not the default.

**Only asymmetric algs; `none` and HMAC rejected.** RS256 (the OIDC default) and EdDSA
(consistent with the fleet's Ed25519 keys, D60) are accepted. The `none` alg — the classic
JWT bypass — and symmetric HS* are refused, and the alg must match the configured key's
type, closing the algorithm-confusion attack (verifying an HMAC/RSA blob against a public
key). This is exactly the class of bug the recurring-pattern lesson warns about: the test
forges a `none` token and an alg-confusion token and asserts both are rejected.

**Same pseudonym + role discipline as the cert producer.** The subject is hashed one-way
(D23) so the raw `sub` never enters the pipeline; the role comes from a configured claim
(an authorization class, in the clear). A missing/empty role is an error — defaulting one
would grant unearned access.

**Producer only — access-proxy composition is deferred.** The access proxy authenticates
by one credential today. Composing a user token WITH a device cert (which credential
carries posture? which subject keys the risk/posture stores?) is a genuine deployment
design fork best decided with the owner, and is staged after this producer exactly as the
client-cert producer (D86) preceded its access wiring (D87).

## Risks / Trade-offs

- **Static keys must be rotated by the operator** until discovery lands; a compromised or
  retired provider key stays trusted until reconfigured. Documented; discovery is the
  hardening.
- **Clock skew:** exp/nbf use the injected clock with no leeway window; a follow-up may
  add a small skew allowance (providers commonly allow ~60s). Erring strict is fail-safe.
