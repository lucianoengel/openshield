## Why

D85 gave the identity context contract and D86 the client-cert identity producer.
This wires them into a live BeyondCorp-style ACCESS BROKER: the gateway authenticates
a client certificate, resolves the verified identity into the pipeline context, makes
an identity-aware per-request access decision through the unchanged pipeline, and
reverse-proxies allowed requests to an internal service — finally replacing the
`sha256(src-IP)` non-identity (D84) with a real verified subject.

## What Changes

- `gateway.Request` gains an OPTIONAL `Identity *core.Context` (nil for egress/forward,
  unchanged).
- `Gateway.Process`: when `req.Identity != nil`, resolve it via the dispatcher's
  `ResolveContext` (D53) so the policy authorizes on `input.context.{identity, role,
  device_posture}` (D85); and `toEvent` stamps `req.Identity.Identity` as the Event
  Subject (the verified pseudonym, D86) instead of `pseudonym(SrcIP)`.
- `gateway.AccessProxy` (http.Handler): require a verified client cert (401 if absent),
  resolve it via `identity.FromClientCert` (403 if not a client identity), run
  `Process` with the identity context, and ALLOW → reverse-proxy to the internal
  service, else → 403.
- ACCESS FAILS CLOSED: a pipeline error denies (403) — the deliberate OPPOSITE of the
  egress proxy's fail-open (D73/D17), because a Zero-Trust gate must never grant entry
  on an error.

## Capabilities

### Modified Capabilities
- `network-gateway`: an identity-aware reverse/access-proxy that authorizes per request
  on the verified identity and fails closed.

## Impact

- `gateway.Request` + `Process` identity threading, new `gateway.AccessProxy`;
  `docs/decisions.md` D87. Reuses the unchanged pipeline, D85 contract, D86 producer.
- Proven with real TLS + real client certs: a finance cert reaches the upstream under
  a finance-authorizing policy (subject = verified pseudonym, not the src IP); a denied
  role → 403 upstream-never-hit; no client cert → 401; a pipeline error → 403 (fail
  closed).
- NOT in scope (stated): the internal-service catalog + per-service microsegmentation +
  binary access-mode config (A.4); OIDC (A.2b); the device-posture producer; the
  risk-publish loop (A.5). Respects D85, D86, D53, D23, D73/D17, D69.
