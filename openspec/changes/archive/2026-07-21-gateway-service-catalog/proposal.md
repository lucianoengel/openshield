## Why

D87 shipped the identity-aware access broker against a SINGLE fixed upstream. A real
Zero-Trust access gateway fronts MANY internal services and authorizes PER SERVICE —
identity-based microsegmentation ("finance → payroll, deny wiki"), replacing IP-based
ACLs (D84). This adds the service catalog and makes the policy see which service is
being accessed.

## What Changes

- `gateway.Catalog` — a registry of internal services: `Add(name, upstream)` (stores a
  per-service `httputil.ReverseProxy`), `Resolve(host)` routes a request to a service.
- `gateway.AccessProxy` takes a `*Catalog` (not a single upstream): resolve the service
  from the request Host; an UNKNOWN service → 404 (don't leak topology, don't forward);
  set `Request.Host` to the service so the Event carries which service is targeted; run
  `Process` (authorize per-service on the identity context); ALLOW → reverse-proxy to
  THAT service; else → 403. Fail-closed + client-cert auth (D87) unchanged.
- `policy.buildInput` exposes `input.event.{host, method, path}` for network events so a
  policy can microsegment. This is the LOCAL in-process policy — telemetry still redacts
  the URL path (D77); local exposure is not a boundary crossing.

## Capabilities

### Modified Capabilities
- `network-gateway`: a service catalog with per-service identity authorization.
- `policy-evaluation`: the policy sees the requested service for microsegmentation.

## Impact

- New `gateway.Catalog`, `AccessProxy` takes a catalog, `buildInput` event projection;
  `docs/decisions.md` D88. The D87 access mechanism is unchanged.
- Proven with real TLS + client certs: the SAME finance identity reaches payroll but is
  denied wiki (microsegmentation); an unknown service → 404.
- NOT in scope (stated): the binary access-mode wiring + file-loaded policy + env catalog
  (A.4b); OIDC (A.2b); the posture producer; the risk loop (A.5); path/wildcard routing.
  Respects D87, D85, D77, D14, D69.
