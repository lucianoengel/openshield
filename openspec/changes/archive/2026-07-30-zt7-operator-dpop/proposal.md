# A stolen operator token was enough to be the operator

## Why

The last security residual from ZT-7. D373 gave operators SSO; the tokens were plain bearer credentials, so
capturing one — from a log, a proxy, shell history, a browser — was equivalent to holding the operator's
identity until it expired.

The codebase already had sender-constraining (RFC 9449 DPoP) for the ZTNA path. The operator path did not
use it.

## What changes

`VerifySubjectWithProof` — the operator equivalent of `VerifyWithProof`: raw subject, no role claim, and a
token carrying `cnf.jkt` requires a DPoP proof under that key bound to the method and URI, single-use,
fresh.

- Proof validation is always enabled on the operator verifier, so a token the issuer bound is always
  checked. It costs nothing when no token is bound.
- `OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP` refuses UNBOUND tokens. Off by default — on before the issuer
  binds would lock everyone out — and it is what stops a provider misconfiguration silently returning every
  operator to a stealable credential.
- A bound token reaching a verifier that cannot check proofs is REFUSED, not downgraded.

The interface the control plane holds has only the proof-aware method. Keeping a plain `VerifySubject`
beside it would leave a path that ignores sender-constraining, and the whole value is that there is no such
path.

## Impact

- No new dependency, no proto change, no migration. Behaviour changes only for tokens that carry `cnf.jkt`.
- Affected capability: **operator-identity**.

## The tests had to move, and a mutation is why

The control-plane cases drive a STUB verifier. They prove the wiring — that the `DPoP` header is read and
passed through — and **a mutation of the real validation left them passing**, because mutating
`identity.OIDCVerifier` cannot affect a stub that implements the interface itself.

So the semantics are asserted in the identity package against the real verifier, where all three mutations
now fail: honouring a bound token without its proof, ignoring the require-bound switch, and downgrading a
bound token when proofs cannot be checked. The stub tests stay, correctly scoped to the wiring.

## Honest limits

- **The `htu` is built from the request's Host header.** Behind a reverse proxy that rewrites it, proofs
  will not match unless the proxy preserves it. Scheme is hardcoded `https` rather than derived from a
  client-controlled header, so a client cannot choose what its own proof must match.
- **Replay rejection is bounded by a cache.** A proof identifier is remembered for the last N; beyond that,
  a very old proof could in principle be replayed inside its freshness window. The window is short and the
  cache is configurable.
- **This does not bind the certificate path.** An operator authenticating with mTLS is already
  sender-constrained by the TLS handshake, which is the equivalent property by a different mechanism.
- SCIM remains the last ZT-7 residual.
