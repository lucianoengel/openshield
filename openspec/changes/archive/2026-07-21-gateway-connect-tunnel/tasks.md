# Tasks — gateway CONNECT blind tunnel (N1.3a)

## 1. CONNECT handling

- [x] 1.1 `Proxy.ServeHTTP`: dispatch `r.Method == http.MethodConnect` to `handleConnect`; keep the plain-HTTP path (D73) unchanged for every other method.
- [x] 1.2 `handleConnect`: dial the upstream `r.Host` (`net.DialTimeout`, 502 on failure); hijack the client connection (`http.Hijacker`); write `HTTP/1.1 200 Connection Established\r\n\r\n`; relay bytes both directions with two `io.Copy` goroutines that close both connections when either finishes.
- [x] 1.3 Log each tunnel at info (host, "not inspected — TLS interception is N1.3b") — the coverage gap is surfaced, not silent (D16). Do NOT run the pipeline on tunneled bytes.

## 2. Proof (guards, each mutation-tested)

- [x] 2.1 **Test**: REAL TLS. `httptest.NewTLSServer` upstream echo + the Proxy on `httptest.NewServer` + a real `http.Client` using the proxy (`http.ProxyURL`) and trusting the upstream cert (RootCAs from `up.Certificate()`). An HTTPS POST succeeds end to end (200, body echoed, upstream hit).
- [x] 2.2 **Test**: the ledger has ZERO entries after the tunneled HTTPS request — the tunneled body was NOT classified (the honest coverage gap that interception closes).
- [x] 2.3 **Test**: a CONNECT to an unreachable upstream returns 502.
- [x] 2.4 **Test**: plain-HTTP forwarding (D73) still works unchanged — the existing proxy suite runs green alongside.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D74: the CONNECT blind tunnel makes HTTPS transit the proxy but does not inspect it; TLS interception (a SEPARATE interception CA — NOT the fleet mTLS CA — plus on-the-fly SNI leaf minting, terminating the inner TLS, classifying the inner HTTP request, re-forwarding over upstream TLS) and the do-not-intercept list are N1.3b; tunneled HTTPS is a stated coverage gap.
- [ ] 3.2 `openspec validate gateway-connect-tunnel --strict`; `make all` + `-race`; doccheck; archive via the skill; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| CONNECT dispatch removed (HTTPS falls into the plain-HTTP path) | `TestProxyTunnelsHTTPSWithoutInspecting` (tunnel breaks + ledger leaks) |

THE VERDICT (D74): the proxy handles CONNECT with a blind TCP tunnel, so HTTPS transits the
proxy end to end — proven with real TLS (httptest TLS upstream + real proxy client) — while
inspecting NOTHING: the ledger stays empty for tunneled traffic, the honest coverage gap that
TLS interception (N1.3b) will close. A dead upstream returns 502; plain-HTTP forwarding (D73)
is unchanged. NOT in scope: TLS interception + a SEPARATE interception CA + the do-not-intercept
list (N1.3b); metadata-only audit of tunneled flows; the worker pool.
