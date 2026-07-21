# Tasks — gateway telemetry projection (D77)

## 1. Redaction

- [x] 1.1 `redactForTelemetry(ev *corev1.Event) *corev1.Event` — clone the Event; on the NetworkSubject clear `src_ip`, `src_port`, `http_path`; keep `dst_ip`/`dst_port`, `sni_host`, `http_method`, `protocol`, `direction`, `flow_id`. Non-network events pass through unchanged.

## 2. Gateway projection

- [x] 2.1 `Gateway` gains an optional `telemetry core.Transport` and `SetTelemetry(core.Transport)`.
- [x] 2.2 `Process`: after `dec` is produced and recorded, if `telemetry != nil` project `redactForTelemetry(ev)` via `PublishEvent` and `dec` via `PublishDecision`; log errors, never fail the request (best-effort, D30/D67).

## 3. Binary

- [x] 3.1 `cmd/openshield-gateway`: when `OPENSHIELD_NATS_URL` + an enrolled identity file are configured, build a `SignedPublisher` (identity + NATS conn, optional seq/queue files, mirroring the fleet agent) and `SetTelemetry`; else projection off.

## 4. Proof (guards, each mutation-tested)

- [x] 4.1 **Test**: FAKE `core.Transport`. A network Process projects exactly one Decision and one Event.
- [x] 4.2 **Test**: the projected Event's NetworkSubject has EMPTY src_ip and EMPTY http_path, but NON-EMPTY sni_host and dst (destination + verdict kept, user IP + URL path dropped).
- [x] 4.3 **Test**: with no telemetry configured (nil), NOTHING is projected (opt-in default).
- [x] 4.4 **Test**: a telemetry publish error does not fail `Process` (best-effort), and the local ledger still recorded the decision.

## 5. Docs, ship

- [x] 5.1 `docs/decisions.md` D77: the gateway projects a boundary-safe network telemetry record (redacted Event metadata — destination + verdict, no user IP, no URL path — plus the Decision) via the existing signed transport; opt-in, additive, best-effort; ClassificationSummary projection a noted follow-up.
- [x] 5.2 `openspec validate gateway-telemetry-projection --strict`; `make all` + `-race`; doccheck; archive via the skill; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| redaction does not clear src_ip/http_path | `TestTelemetryProjectsRedacted` |
| project even when the projector is nil | `TestTelemetryOffByDefault` (nil deref / no opt-in) |

THE VERDICT (D77): the gateway projects a boundary-safe view of each decision — a redacted network
Event (destination + verdict kept; user IP + URL path dropped) plus the Decision — to the control plane
via the existing signed transport; opt-in, additive to the local ledger, best-effort with offline
queue. The `enroll` helper was extracted to `internal/agent/enroll` for reuse by both binaries. NOT in
scope: ClassificationSummary projection; full-URL projection; async projection.
