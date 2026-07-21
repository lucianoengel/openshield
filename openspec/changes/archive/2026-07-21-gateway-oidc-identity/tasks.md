# Tasks — OIDC identity producer (D93)

## 1. Producer

- [x] 1.1 `identity.OIDCVerifier` + `NewOIDCVerifier`/`WithClock`; `Verify` validates iss/aud/exp/nbf/signature (RS256+EdDSA), pseudonymous subject (D23), role from configured claim; every failure fail-closed; `none`/HMAC/alg-confusion rejected.

## 2. Proof (guards mutation-tested)

- [x] 2.1 **Test**: valid EdDSA + RS256 tokens resolve to a pseudonymous subject (no raw-identity leak) + role; adversarial tokens (tampered EdDSA/RS256 sig, wrong iss, wrong aud, expired, not-yet-valid, unknown kid, missing role, empty subject, `none` alg, not-a-jwt) all rejected; alg-confusion (RS256 blob vs Ed25519 key) rejected; bad config errors.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D93.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| unsafe alg default returns nil (accept `none`) | `none`-alg adversarial token accepted |
| issuer check skipped | wrong-issuer token accepted |
| expiry check skipped | expired token accepted |
| RS256 signature error ignored | tampered-RS256-signature token accepted |
| RS256 key-type check removed (alg confusion) | alg-confusion token accepted |
