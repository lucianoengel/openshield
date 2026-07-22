## Why

PLAT-4 (P1). There is no Prometheus/OTel/`/metrics` endpoint anywhere. The control plane
already maintains "no silent loss" counters (dropped/rejected/gapped telemetry) — but they are
internal-only, so an operator cannot ALERT on them. This exposes them. (OTel was consciously
cut from Phase 1; this is a deliberate re-opening for enterprise operability.)

## What Changes

- `Server.MetricsHandler` — the operational counters in the Prometheus text exposition format,
  dependency-free (no client library, no supply-chain surface).
- `cmd/openshield-server`: an opt-in `/metrics` endpoint on a SEPARATE address
  (`OPENSHIELD_METRICS_ADDR`), unauthenticated by convention (a scrape target).

## Capabilities

### Added Capabilities
- `observability`: a metrics endpoint exposes the control plane's operational counters.

## Impact

- New `internal/controlplane/metrics.go`; server-binary wiring; `docs/decisions.md` D127.
- Proven: the handler emits the live counter values (dropped/gaps/rejected) in valid Prometheus
  format (HELP + TYPE + value lines, text/plain content type). Guard mutation-tested (hardcode a
  counter to 0 → the live-value assertion fails).
- NOT in scope (stated): OTel spans/traces (a larger, deliberately-deferred surface); metrics
  for the gateway/engine binaries (the same pattern applies — a follow-up); histograms/gauges
  (only counters today); auth on the endpoint (unauthenticated by Prometheus convention — deploy
  it on an internal/firewalled address; the values are counts only, no subject/content, D10/D29).
