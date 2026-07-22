## 1. The keyFor seam on the verifier

- [x] 1.1 `OIDCVerifier` gains `keyFor func(kid string) (crypto.PublicKey, bool)`; `Verify` calls it
      instead of indexing `v.keys`. `NewOIDCVerifier` sets `keyFor` to close over the static map (same
      behavior). Add `SetKeySource(keyFor)` (or a constructor) to wire an external source.

## 2. JWKSRefresher

- [x] 2.1 `jwks.go`: `JWKSRefresher{url, client, snapshot (RWMutex map), minInterval, trigger chan, now}`;
      `NewJWKSRefresher(url, interval)`. JWK parsing: `kty=RSA` (n,e base64url → *rsa.PublicKey),
      `kty=OKP crv=Ed25519` (x base64url → ed25519.PublicKey); other kty skipped.
- [x] 2.2 `refresh(ctx)`: GET the URL, parse, build a fresh kid→key map, atomic-swap under the write
      lock; on ANY fetch/parse error return it and KEEP the previous snapshot (serve-stale).
- [x] 2.3 `Start(ctx)`: refresh once immediately, then on a ticker AND on `trigger` — a trigger-driven
      refresh is SKIPPED if within `minInterval` of the last (rate limit).
- [x] 2.4 `keyFor(kid)`: RLock read the snapshot; on a MISS non-blocking-send to `trigger` and return
      not-found. NEVER fetch here.

## 3. Wire it (opt-in)

- [x] 3.1 `cmd/openshield-gateway`: when `OPENSHIELD_OIDC_JWKS_URL` is set, build a `JWKSRefresher`,
      `Start` it, and `SetKeySource(refresher.keyFor)` on the OIDC verifier; else keep the static PEM
      keys (`LoadOIDCKeys`), unchanged.

## 4. Verify + mutation guards

- [x] 4.1 Test (real httptest JWKS server): the refresher fetches; `keyFor` returns a fetched key and a
      token signed by it verifies. A NEW kid served after a rotation is picked up by a refresh and its
      token verifies. JWK parse round-trips an RSA and an Ed25519 key.
- [x] 4.2 Test: with the JWKS endpoint failing AFTER a good fetch, `keyFor` still serves the last-good
      key (serve-stale). A kid-miss triggers a refresh but is rate-limited (N misses → ≤1 fetch per
      interval, asserted via a request-counting handler). The verify path issues no fetch (a token
      verify does not increment the JWKS server's request count).
- [x] 4.3 Mutation guards (apply, FAIL, revert): (A) make `keyFor` fetch synchronously on a miss → the
      no-fetch-on-request-path / rate-limit assertion FAILs; (B) `refresh` clears the snapshot on error →
      the serve-stale assertion FAILs. Record it. (Confirmed 2026-07-22: (A) sync fetch on miss -> KeyForNeverFetches sees 100 fetches -> FAIL; (B) clear snapshot on error -> rsa2 not resolvable after endpoint down -> FAIL; both reverted.)

## 5. Gate + record

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...` clean.
- [x] 5.2 decisions.md entry (next D-number); note OIDC discovery deferred, static PEM path preserved.
- [x] 5.3 Roadmap + memory updated.
