## Context

`OIDCVerifier.Verify` looks up the signing key with `key, ok := v.keys[h.Kid]` against a static map
loaded from PEM files. An IdP key rotation makes the token's new `kid` unknown → every token rejected
until an operator redistributes keys and restarts. ADR-7 chooses a background JWKS refresher, with
three hard constraints: serve-stale on a fetch failure, rate-limit the kid-miss refresh, and never
fetch on the request path.

## Goals / Non-Goals

**Goals:**
- Pick up rotated IdP keys automatically, without a restart.
- Decouple the verify/request path from IdP availability (serve-stale) and from IdP load (rate-limit).
- Keep the request path HTTP-free; keep the fail-closed verification (D93) unchanged.

**Non-Goals:**
- OIDC discovery (`/.well-known/openid-configuration`) — the JWKS URL is configured directly; discovery
  is a later refinement.
- Rotating the issuer/audience config; changing any verification check.
- Replacing the static-PEM path (it stays for air-gapped/offline deployments).

## Decisions

### D-a · The verifier's key lookup is a `keyFor(kid)` seam
`OIDCVerifier` gains `keyFor func(kid string) (crypto.PublicKey, bool)` and `Verify` calls it instead of
indexing the map. `NewOIDCVerifier` sets `keyFor` to close over the static map (byte-for-byte the same
behavior). A `SetKeySource(keyFor)` (or a `NewOIDCVerifierWithKeySource`) wires the refresher. The seam
is the whole integration surface — no verification logic changes.

### D-b · `JWKSRefresher`: background fetch, atomic snapshot, serve-stale
`JWKSRefresher{url, client, snapshot (RWMutex-guarded map), minInterval, trigger chan}`:
- `refresh(ctx)`: `GET url`, parse each JWK to a `crypto.PublicKey`, build a fresh `kid→key` map, and
  swap it under the write lock. On ANY fetch/parse error it returns the error and LEAVES the previous
  snapshot in place — serve-stale, so a transient IdP outage does not black out auth.
- `Start(ctx)`: a goroutine that refreshes once immediately, then on a periodic ticker AND whenever the
  `trigger` fires — but a trigger-driven refresh is skipped if the last refresh was within
  `minInterval` (the rate limit).
- `keyFor(kid)`: read the snapshot under the read lock; on a MISS, non-blocking send to `trigger`
  (a `kid` the current snapshot lacks — likely a rotation), then return not-found. It NEVER fetches —
  all HTTP is in `Start`'s goroutine, so the request path is HTTP-free.

*Alternative considered:* fetch synchronously on a kid-miss. **Rejected** — it couples the request path
to IdP latency/availability and is a DoS amplifier (each unknown-kid token = an outbound fetch); the
background+rate-limited trigger gives the same eventual-consistency without either hazard.

### D-c · JWK → crypto.PublicKey for the two supported algorithms
Parse `keys[]`: `kty=RSA` → decode base64url `n` (modulus) and `e` (exponent) into an `*rsa.PublicKey`;
`kty=OKP, crv=Ed25519` → decode base64url `x` (32 bytes) into an `ed25519.PublicKey`. Anything else is
skipped (the verifier already rejects unsupported algs). These are exactly the key types `Verify`
accepts, so no new algorithm surface is introduced.

### D-d · Rate-limited, eventual pickup of a rotated key
A token with a rotated `kid` fails the first time (the snapshot predates the rotation) and triggers a
rate-limited refresh; the next token with that `kid`, after the refresh lands, verifies. Fail-closed in
the gap (an unknown key is never trusted), self-healing within one refresh — the correct trade for a
security boundary.

## Risks / Trade-offs

- **A brief window where a just-rotated key is not yet known** → fail-closed (reject), self-heals on the
  next refresh; the periodic interval bounds it even without a kid-miss trigger.
- **Serve-stale during an IdP outage** → intended: a token signed by a still-valid (not-yet-rotated) key
  keeps verifying; only genuinely new keys are unavailable until the IdP returns.
- **JWK parse of malformed provider data** → a bad JWK is skipped (or the whole refresh errors and
  serves stale); never panics, never trusts a malformed key.

## Migration Plan

Additive and opt-in: set `OPENSHIELD_OIDC_JWKS_URL` to enable the refresher; unset keeps the static PEM
path. No proto/schema change. Rollback = unset the env.

## Open Questions

None. OIDC discovery is a deliberate later refinement (the JWKS URL is configured directly for now).
