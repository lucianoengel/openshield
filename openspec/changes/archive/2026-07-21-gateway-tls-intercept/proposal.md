## Why

D74 made HTTPS transit the proxy via a blind tunnel, but tunneled bodies are
uninspected — the dominant egress path is a coverage gap. This change closes it:
TLS interception. The gateway terminates the client's TLS with a certificate it
mints on the fly (signed by a SEPARATE interception CA), classifies the inner HTTP
request through the same pipeline as plain HTTP, and re-forwards to the origin over
a fresh TLS connection. A do-not-intercept list tunnels cert-pinned and sensitive
hosts blind, the safe default.

## What Changes

- `provision.InterceptionCA()` — a SEPARATE CA generator (distinct CN, IsCA,
  cert-sign), deliberately NOT the fleet mTLS CA: a MITM root can present a trusted
  cert for ANY host, impersonating the whole internet to the fleet — a far larger
  blast radius than fleet identity (D74's recorded reasoning made real). Deployed
  as a trusted root only where interception is authorised.
- `internal/gateway.CertMinter` — loads the interception CA cert+key and mints (and
  caches) an Ed25519 leaf per SNI hostname as a `tls.Config.GetCertificate`
  callback; empty SNI is rejected.
- A do-not-intercept list (exact host + domain suffix) — hosts tunneled blind even
  with interception on (pinned apps break under MITM; banking/health are sensitive).
- `Proxy.handleConnect` intercepts when interception is enabled and the host is not
  excluded, else blind-tunnels (D74). `intercept()` terminates the client TLS with a
  minted leaf and serves HTTP/1.1 on the decrypted connection, running each inner
  request through the SAME pipeline as plain HTTP; `ServeHTTP`'s body is refactored
  into a shared `serve(w, r, targetURL, rt)` so classify/decide/enforce/fail-open
  are identical for intercepted HTTPS and plain HTTP.
- `cmd/openshield-gateway` loads the interception CA + do-not-intercept list from
  env; interception is on only when a CA is configured (observe-only + plain-HTTP
  stay the defaults).

## Capabilities

### Modified Capabilities
- `network-gateway`: intercepts HTTPS — terminates the client TLS with a minted
  leaf, classifies the inner request, and re-forwards over origin TLS; a
  do-not-intercept list tunnels excluded hosts blind.
- `provisioning`: a separate interception CA generator, distinct from the fleet CA.

## Impact

- New `internal/gateway.CertMinter`, the do-not-intercept matcher, `intercept()`;
  `provision.InterceptionCA()`; the `serve()` refactor; `cmd/openshield-gateway`
  config; `docs/decisions.md` D75. Reuses the D70 pipeline, D72 worker path, D73
  forward/disposition logic, and D74 tunnel fallback unchanged.
- Proven with REAL TLS end to end (in-test interception CA trusted by the client,
  in-test TLS origin trusted by the gateway): an intercepted CPF body is CLASSIFIED
  (ledger entry — D74 gap closed) and forwarded; a BLOCK inner request → 403, origin
  never hit; a do-not-intercept host is tunneled (no ledger entry).
- NOT in scope (stated): revocation/rotation for the interception CA; HTTP/2 and
  QUIC interception; a metadata-only audit of tunneled flows; the worker pool.
  Respects D1/D49, D73, D74, D10/D29, D16 (CA custody is the whole scheme's trust).
