## Why

The Zero-Trust access loop (D87 broker, D88 microsegmentation, D89 continuous
verification) is proven in tests but nothing runs as a binary. This wires the
AccessProxy into `cmd/openshield-gateway` as an ACCESS MODE, so the ZT access gateway
is actually deployable.

## What Changes

- `gateway.ParseCatalog(spec)` — parse `"name=url,name2=url2"` into a `*Catalog` (a bad
  entry or host-less URL is an error, not silently skipped); `Catalog.Len()`.
- `cmd/openshield-gateway` ACCESS-MODE branch (`OPENSHIELD_ACCESS_MODE`): reuse the
  worker pool + ledger, load the identity-aware access POLICY from a file
  (`OPENSHIELD_ACCESS_POLICY`, a default-deny policy the operator writes, D87), parse
  the catalog (`OPENSHIELD_ACCESS_CATALOG`), build `NewAccessProxy` + a `RiskStore`,
  and serve over TLS that REQUIRES a client certificate (RequireAndVerifyClientCert;
  client CA + server cert/key from env) on `OPENSHIELD_ACCESS_LISTEN`.
- Config is fail-fast and loud: a missing client CA, server cert, policy, or empty
  catalog aborts startup — a ZT gate must never boot misconfigured and permissive. A
  gateway runs as egress OR access, not both.

## Capabilities

### Modified Capabilities
- `network-gateway`: a runnable client-cert access-proxy mode.
- `packaging`: the access-gateway binary configuration.

## Impact

- New `gateway.ParseCatalog`/`Len`, an access-mode branch in the gateway binary;
  `docs/decisions.md` D90. Reuses the D87/D88/D89 mechanisms, the worker pool, ledger.
- Proven: a ParseCatalog unit test (valid spec resolves both services; bad entry/URL
  error; empty errors); the binary builds; the deps guard stays green (still spawns the
  worker, doesn't link the parser).
- NOT in scope (stated): the server→gateway risk-publish channel (A.5b); a hardened
  access-mode systemd unit variant (D84 covers isolation); OIDC (A.2b); the posture
  producer; catalog/policy hot-reload. Respects D87/D88/D89, D86, D72/D84, D68.
