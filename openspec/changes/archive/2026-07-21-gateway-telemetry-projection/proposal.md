## Why

The gateway records every Decision to its local forward-secure ledger (the system
of record), but the control plane has no visibility into network decisions — the
fleet view sees file events, not network verdicts. This projects a boundary-safe
network telemetry record to the control plane through the existing signed transport,
so the server learns the destination and verdict without the user's IP or the
sensitive URL path.

## What Changes

- `internal/gateway.Gateway` gains an OPTIONAL telemetry `core.Transport` (nil = no
  projection, the default — opt-in and additive, never the system of record).
  `SetTelemetry(core.Transport)` avoids constructor churn.
- In `Process`, after a Decision is produced and recorded locally, if telemetry is
  configured, project a BOUNDARY-SAFE copy: a redacted network Event + the Decision
  (already boundary-safe by schema, D14). Best-effort — a projection error is
  logged, never fatal; the request is not failed on it (the local ledger is the
  system of record, D30; the publisher offline-queues, D67).
- `redactForTelemetry` clears the NetworkSubject's `src_ip`/`src_port`
  (user-identifying — the Event.Subject already carries the pseudonym, D23) and
  `http_path` (path+query can carry tokens/emails/search terms — content-like),
  while KEEPING the destination (`dst_ip`/`port`, `sni_host`), `http_method`,
  `protocol`, `direction`, and `flow_id`.
- `cmd/openshield-gateway`: when `OPENSHIELD_NATS_URL` and an enrolled identity are
  configured, build a `SignedPublisher` and `SetTelemetry`; else projection is off.

## Capabilities

### Modified Capabilities
- `network-gateway`: projects each Decision (with redacted network metadata) to the
  control plane, opt-in and additive to the local ledger.
- `event-transport`: a boundary-safe network telemetry projection that redacts the
  user IP and the URL path before crossing to the control plane.

## Impact

- `internal/gateway` (telemetry field + redaction), `cmd/openshield-gateway`
  wiring, `docs/decisions.md` D77. Reuses `core.Transport` and the signed publisher
  unchanged.
- Proven with a fake `core.Transport` (no NATS): a network Process projects one
  Decision + one redacted Event (empty src_ip/http_path, non-empty sni_host/dst);
  nil telemetry projects nothing; a publish error does not fail Process.
- NOT in scope (stated): projecting the ClassificationSummary (detector types) —
  needs the classification plumbed out of Process; full-URL projection under an
  explicit policy opt-in; async projection. Respects D10/D29, D23, D30, D41/D44, D67.
