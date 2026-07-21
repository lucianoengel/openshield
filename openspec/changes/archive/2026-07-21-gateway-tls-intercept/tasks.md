# Tasks — gateway TLS interception (N1.3b)

## 1. Interception CA (provision)

- [x] 1.1 `provision.InterceptionCA()` — a separate CA generator (distinct CN "OpenShield Interception CA", IsCA, KeyUsageCertSign), NOT the fleet mTLS CA. Returns cert+key PEM.

## 2. Cert minter (internal/gateway.CertMinter)

- [x] 2.1 `CertMinter` loads the interception CA cert+key PEM; `For(hello)`/`ForHost(host)` mint (and cache, mutex-guarded) an Ed25519 leaf for the host (DNSNames for a hostname, IP SAN for an IP literal) signed by the CA; empty host is rejected.

## 3. Do-not-intercept list

- [x] 3.1 A matcher over hosts: exact host OR domain suffix. `intercepts(host) bool` = a minter is configured AND host not matched.

## 4. Proxy: intercept path + shared serve()

- [x] 4.1 Refactored `ServeHTTP`'s plain-HTTP body into `serve(w, r, targetURL string, rt http.RoundTripper)` (read bounded → register flow → Process → disposition forward/block/redirect, fail-open). Plain path calls `serve(w, r, r.URL.String(), p.rt)`. `requestFromHTTP` uses `r.Host` for the destination.
- [x] 4.2 `handleConnect`: if `intercepts(hostOnly(r.Host))` → `startIntercept`; else blind tunnel (D74) unchanged.
- [x] 4.3 `intercept()`: hijack + 200; `tls.Server(clientConn, {GetCertificate: <SNI-or-connect-host>, NextProtos:["http/1.1"]})`; serve HTTP/1.1 on the decrypted conn via `http.Serve` over a one-shot listener whose served conn closes the listener on close (so Serve returns only when the conn is done); handler reconstructs `https://<host><uri>` and calls `serve(w, r, thatURL, p.originRT)`.
- [x] 4.4 `EnableInterception(minter, noIntercept, originRT)` turns it on (nil minter = interception off, D74 tunnel); `NewProxy` defaults `originRT` to `http.DefaultTransport`.

## 5. Binary

- [x] 5.1 `cmd/openshield-gateway`: loads the interception CA from `OPENSHIELD_INTERCEPT_CA_CERT`/`_KEY` files and the list from `OPENSHIELD_NO_INTERCEPT`; enables interception only when a CA is configured, with a loud warning. Observe-only + tunnel remain the defaults.

## 6. Proof (guards, each mutation-tested)

- [x] 6.1 **Test**: REAL TLS end to end. In-test interception CA; a client trusting it (RootCAs) + using the proxy; an httptest TLS origin the gateway's `originRT` trusts. An intercepted HTTPS POST whose body carries a CPF → CLASSIFIED (a ledger entry appears — D74 gap closed) and FORWARDED (origin hit, response returned).
- [x] 6.2 **Test**: a BLOCK policy on the inner intercepted request → 403, origin NEVER hit.
- [x] 6.3 **Test**: a host on the do-not-intercept list → TUNNELED (no ledger entry) even with interception enabled.
- [x] 6.4 **Test**: `CertMinter` unit — mints a leaf for an SNI that chains to the CA (verifies) and is cached; empty SNI rejected.

## 7. Docs, ship

- [x] 7.1 `docs/decisions.md` D75: TLS interception via a SEPARATE interception CA + on-the-fly SNI leaf minting; the inner request runs the SAME pipeline as plain HTTP; the do-not-intercept list is the safe-default tunnel for pinned/sensitive hosts; interception is opt-in and its CA custody is the whole scheme's security (D16).
- [ ] 7.2 `openspec validate gateway-tls-intercept --strict`; `make all` + `-race`; doccheck; archive via the skill; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| `intercepts` ignores the do-not-intercept list (always intercept) | `TestDoNotInterceptTunnelsExcludedHost` |
| intercept path forwards without running the pipeline | `TestInterceptClassifiesAndForwardsHTTPS` (no ledger entry) |
| minter omits the IP SAN for an IP-literal host | `TestInterceptClassifiesAndForwardsHTTPS` (leaf rejected) |
| minter accepts an empty SNI | `TestCertMinterRejectsEmptySNI` |

THE VERDICT (D75): TLS interception closes the HTTPS coverage gap — the gateway terminates the
client TLS with a leaf minted (on the fly, cached) by a SEPARATE interception CA, classifies the
inner request through the SAME pipeline as plain HTTP (worker-classify → decide → audit →
disposition, fail-open), and re-forwards over origin TLS; a do-not-intercept list tunnels
pinned/sensitive hosts blind. Proven with real TLS end to end. Opt-in; CA custody is the whole
scheme's security (D16). NOT in scope: revocation/rotation; HTTP/2 + QUIC interception;
metadata-only audit of tunneled flows; the worker pool.
