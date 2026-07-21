# Tasks — identity-aware access proxy (D87)

## 1. Identity threading (gateway)

- [x] 1.1 `gateway.Request` gains `Identity *core.Context` (nil for egress).
- [x] 1.2 `Gateway.Process`: when `req.Identity != nil`, set `disp.ResolveContext` to return it (D53); `toEvent` uses `req.Identity.Identity` as the Event Subject when set (else pseudonym(SrcIP)).

## 2. Access proxy (gateway.AccessProxy)

- [x] 2.1 `AccessProxy` (http.Handler) fronting a fixed internal upstream (`httputil.ReverseProxy`). `NewAccessProxy(gw, upstream, logger)`.
- [x] 2.2 `ServeHTTP`: require a verified client cert (401 if absent); `identity.FromClientCert` (403 if not a client identity); read body bounded; `gw.Process` with `Identity: id.Context()`; ALLOW → reverse-proxy (buffered body reset); else → 403. A pipeline error → 403 (FAIL CLOSED — the opposite of egress fail-open).

## 3. Proof (guards, each mutation-tested)

- [x] 3.1 **Test** (real TLS + client certs): a finance client cert + an access policy authorizing "finance" → the request reaches the httptest internal upstream and returns; the recorded Event subject is the verified pseudonym (not the src IP, not the raw identity).
- [x] 3.2 **Test**: a wrong-role client (policy denies) → 403 and the upstream is NEVER hit.
- [x] 3.3 **Test**: a request with no client cert → 401 (or handshake refused), upstream never hit.
- [x] 3.4 **Test**: a pipeline error (erroring worker) → 403 (fail CLOSED), upstream never hit.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D87: the identity-aware access-proxy mode — Request carries a resolved identity Context, Process resolves it (D53) and stamps the verified pseudonym as the subject (replacing sha256(src-IP), D84); AccessProxy authenticates a client cert (D86), authorizes per request on the identity context (D85), reverse-proxies allowed requests; ACCESS fails CLOSED on error (the opposite of egress fail-open, D73/D17). Catalog + binary wiring = A.4.
- [x] 4.2 `openspec validate gateway-access-proxy --strict`; `make all` + `-race`; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| access fails OPEN on a pipeline error | `TestAccessProxyFailsClosedOnError` |
| the access verdict is ignored (forward regardless) | `TestAccessProxyAuthorizesByIdentity` (sales reaches the service) |
| Process ignores the identity subject (keeps src-IP) | `TestAccessRequestSubjectIsVerifiedIdentity` |

THE VERDICT (D87): the gateway authenticates a client cert (D86), authorizes per request on the verified
identity context (D85) through the unchanged pipeline, stamps the verified pseudonym as the subject
(replacing sha256(src-IP), D84), reverse-proxies allowed requests to an internal service, and FAILS
CLOSED on error (the opposite of the egress fail-open). Proven on real TLS with real client certs. NOT
in scope: the service catalog + binary wiring (A.4), OIDC (A.2b), posture producer, risk loop (A.5).
