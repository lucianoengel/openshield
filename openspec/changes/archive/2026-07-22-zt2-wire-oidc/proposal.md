# ZT-2: wire the OIDC/JWT verifier into the access proxy (SSO)

## Why

`identity/oidc.go` is a complete, well-tested OIDC/JWT verifier — it validates issuer, audience,
expiry/not-before, and signature, and REJECTS the `none` alg and HMAC-vs-RSA algorithm-confusion
attacks. But NO binary constructs it: the access proxy authenticated only by client certificate, so
there was no SSO path. This wires the verifier in, so a user's identity can come from a verified
bearer token issued by an identity provider.

## What Changes

- **`AccessProxy.SetOIDCVerifier`**: when a verifier is configured, the access handler resolves the
  request's USER identity from a verified `Authorization: Bearer <jwt>` token (subject + role from
  the token's claims), LAYERED on the mTLS DEVICE certificate the connection already requires. A
  missing token is 401, an invalid token is 403 (generic messages), and the token's identity feeds
  the same policy context as a cert identity. Without a verifier, the client certificate is the
  identity (unchanged).
- **`identity.LoadOIDCKeys`**: loads a directory of `<kid>.pem` public keys into the verifier's
  kid→key map (static-key wiring).
- **The gateway constructs the verifier** when `OPENSHIELD_OIDC_ISSUER` is set (audience, role claim,
  keys dir from env), aborting startup on a misconfigured OIDC block — a ZT gate must not come up
  with a broken identity source.

## Impact

- Affected specs: `network-gateway`
- Affected code: `internal/gateway/access.go` (SetOIDCVerifier + token resolution),
  `internal/gateway/identity/oidc.go` (LoadOIDCKeys), `cmd/openshield-gateway/main.go` (wiring).
- Not in scope (stated): LIVE JWKS discovery (fetching + caching the issuer's rotating keys — a
  conscious follow-up, because an outbound fetch at the gateway chokepoint wants its own
  timeout/failure posture, not a silent dependency; static keys are wired now); dual-credential
  composition of token-user + cert-device into one authorization (ZT-3 — the device cert is required
  by mTLS but not yet composed into the identity context); token refresh / a login flow (the token is
  presented by the client).
