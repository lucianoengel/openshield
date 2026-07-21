## Why

Audit gap #2: the two things a security team most needs to SEE — peer-UEBA
detections (`peer_alerts`) and silent/overdue agents (`Server.Overdue`) — have ZERO
read API. `peer_alerts` is only ever read by `psql` in tests, and `Server.Overdue`
has zero production callers. This gives the operator a read surface over the fleet,
behind the same mutual-TLS operator-role gate `/view` already uses.

## What Changes

- `Server.RecentPeerAlerts(ctx, limit)` — recent peer alerts (subject stays
  pseudonymous, D23) as a `[]PeerAlert`.
- `Server.OperatorReadHandler()` — a mux serving GET `/alerts` (RecentPeerAlerts as
  JSON, `?limit=` default 100) and GET `/overdue` (`Server.Overdue(threshold, now)`
  as JSON, `?threshold=` default 15m) — wiring the dead-man's-switch and peer-UEBA to
  a reader.
- `ServeHTTPTLS` mounts both behind `requireRole(RoleOperator)`, exactly as `/view`
  is. Read-only (no signer, forge-nothing — the D30 asymmetry), mutual-TLS only.

## Capabilities

### Modified Capabilities
- `control-plane`: an operator read API over peer alerts and overdue agents, behind
  cert-role operator authz.

## Impact

- New `Server.RecentPeerAlerts` + `OperatorReadHandler`, two routes in ServeHTTPTLS;
  `docs/decisions.md` D82. No proto/pipeline change.
- Proven (real Postgres + the operator-cert test harness): operator GET /alerts and
  /overdue return JSON; an agent cert gets 403; unauthenticated gets 401.
- NOT in scope (stated): a UI (this is the API it would use); an operator-read audit
  row for aggregate reads; pagination beyond limit+threshold; a telemetry search API.
  Respects D56/D58, D23, D30, D47.
