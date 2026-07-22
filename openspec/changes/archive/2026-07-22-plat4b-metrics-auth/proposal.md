# PLAT-4b: metrics endpoint auth + non-loopback bind guard

## Why

The `/metrics` endpoint (PLAT-4) has no authentication and nothing stops it being bound to a
non-loopback address. Its counters leak fleet operational tempo — rejected/gapped/dropped-telemetry
counts are reconnaissance for a replay or flood attempt (an attacker watches whether their forged
telemetry is being rejected). Exposed on a public interface with no auth, it is a recon surface. This
should be locked down before per-host (gateway/engine) metrics multiply the exposure.

## What Changes

- **Optional bearer-token auth**: when `OPENSHIELD_METRICS_TOKEN` is set, `/metrics` requires an
  `Authorization: Bearer <token>` header, compared in constant time; without it, 401.
- **Non-loopback bind guard**: the server warns LOUDLY at startup when the metrics endpoint is bound
  beyond loopback (`:9090`, `0.0.0.0`, a routable IP, a hostname) WITHOUT a token — an unauthenticated
  scrape target on a public interface is flagged, not silently exposed.

## Impact

- Affected specs: `observability`
- Affected code: `internal/controlplane/metrics_auth.go` (new: RequireBearerToken, IsNonLoopbackBind),
  `cmd/openshield-server/main.go` (wire token + warning).
- Not in scope (stated): mutual-TLS on the metrics endpoint (a bearer token + loopback-by-default is
  the pragmatic first step; mTLS is a heavier deployment option); per-host gateway/engine metrics
  endpoints (they adopt the same guard when added); refusing to bind non-loopback outright (a warning
  preserves the operator's ability to run behind their own network controls).
