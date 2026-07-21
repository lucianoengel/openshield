# Tasks — service catalog + microsegmentation (D88)

## 1. Catalog

- [x] 1.1 `gateway.Catalog`: `NewCatalog()`; `Add(name string, upstream *url.URL)` (stores a per-service `httputil.ReverseProxy`); `Resolve(host string) (*service, bool)` exact-match host routing.

## 2. AccessProxy routes per-service

- [x] 2.1 `NewAccessProxy(gw, catalog, maxBody, logger)` takes a `*Catalog` (update the D87 tests to a one-service catalog). `ServeHTTP`: after client-cert auth, `Resolve(hostOnly(r.Host))`; unknown → 404; set `Request.Host` = service name; `Process`; ALLOW → the service's reverse proxy; else → 403; fail-closed on error (D87) unchanged.

## 3. Policy sees the service

- [x] 3.1 `policy.buildInput`: for a network Event, add `input.event.{host, method, path}` from the NetworkSubject (local policy; telemetry still redacts the path, D77).

## 4. Proof (guards, each mutation-tested)

- [x] 4.1 **Test** (real TLS + client certs): catalog {payroll, wiki}; a policy allowing role finance to host payroll only; a finance client → reaches PAYROLL (200, payroll hit) and is DENIED wiki (403, wiki NEVER hit) — microsegmentation.
- [x] 4.2 **Test**: an unknown service host → 404, no upstream hit.
- [x] 4.3 **Test**: `Catalog` unit — Add/Resolve; an unknown host is not found.

## 5. Docs, ship

- [x] 5.1 `docs/decisions.md` D88: the service catalog + per-service microsegmentation — route per-request to a catalogued service, unknown = 404 (not an open relay), the policy sees the service host/method/path for identity-based microsegmentation replacing IP ACLs (D84); telemetry still redacts the path (D77); binary access-mode wiring = A.4b.
- [x] 5.2 `openspec validate gateway-service-catalog --strict`; `make all` + `-race`; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| unknown service not refused (open relay) | `TestAccessUnknownServiceRefused` |
| event.host not exposed to policy (microseg blind) | `TestAccessMicrosegmentation` |

THE VERDICT (D88): the access proxy fronts a catalog of internal services (an allow-list — unknown = 404,
never an open relay), routes per-service, and authorizes per-service on the identity — the SAME finance
identity reaches payroll but is denied wiki (identity-based microsegmentation, replacing IP ACLs, D84).
buildInput exposes the service host/method/path to the LOCAL policy; telemetry still redacts the path
(D77). Proven with real TLS + client certs. NOT in scope: binary access-mode wiring (A.4b), OIDC (A.2b),
posture producer, risk loop (A.5), path/wildcard routing.
