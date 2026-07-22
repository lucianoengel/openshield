## Why

The OIDC verifier's signing keys are static. `OIDCVerifier` holds a `kid → public key` map loaded once
from PEM files, so an identity provider's routine key rotation (Okta, Entra) breaks token verification
until an operator redistributes the keys and restarts the gateway. Real IdP integration needs the
gateway to pick up rotated keys on its own — but fetching keys must not couple the request path to the
IdP's availability, nor let a flood of unknown-key tokens hammer the IdP. ADR-7: a background JWKS
refresher that serves stale on a fetch failure, refreshes rate-limited on a `kid` miss, and never
fetches on the request path.

## What Changes

- A `JWKSRefresher` fetches the provider's JWKS over HTTP in a **background** goroutine and keeps an
  atomically-swapped `kid → key` snapshot. On any fetch/parse failure it **keeps the previous
  snapshot** (serve-stale — auth availability is decoupled from the IdP).
- The verifier's key lookup goes through a `keyFor(kid)` seam that **only reads the snapshot** — the
  verify/request path issues no HTTP. A `kid` miss signals the refresher to refresh soon, **rate-limited**
  to at most once per min-interval, so an unknown-`kid` flood cannot hammer the IdP.
- JWK parsing supports the two algorithms the verifier already accepts: RSA (`kty=RSA`) and Ed25519
  (`kty=OKP, crv=Ed25519`).
- `NewOIDCVerifier` keeps its static-map behavior; the refresher is wired via the key-source seam.
  `cmd/openshield-gateway` uses the refresher when `OPENSHIELD_OIDC_JWKS_URL` is set (else the current
  static PEM keys, unchanged).

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `network-gateway`: OIDC token verification resolves signing keys from a live, rotation-safe JWKS
  source — refreshed in the background, serving the last-good keys on a fetch failure, rate-limited on
  an unknown-key-id miss, and never fetching on the request path.

## Impact

- **Code:** `internal/gateway/identity` (a `jwks.go` refresher + JWK parsing; a `keyFor` seam on the
  verifier), `cmd/openshield-gateway` (wire the refresher when configured), and tests.
- **No proto/core change.** Backward compatible: with no JWKS URL, the static PEM-key path is unchanged;
  the verify path's fail-closed checks (D93) are untouched — only key SOURCING changes.
