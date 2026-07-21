## Context

The endpoint projects telemetry to the control plane via `core.Transport`
(PublishEvent/Classification/Decision), implemented by `natsx.SignedPublisher`
(signed with the enrolled identity, verified and persisted by the control plane,
D41/D44, offline-queued, D67). The gateway records Decisions only to its local
ledger. The network Event carries `NetworkSubject` metadata — including `src_ip`
(the user) and `http_path` (the URL) — which is more sensitive than a file path
(D69/D73 flagged it as the gateway's DPIA scope).

## Goals / Non-Goals

**Goals:**
- Give the control plane a boundary-safe view of network verdicts (destination +
  action), reusing the signed transport.
- Redact user-identifying and content-like fields before crossing the boundary.
- Keep the local ledger the system of record; projection is additive and opt-in.

**Non-Goals:**
- Projecting the ClassificationSummary (needs the classification out of Process);
  full-URL projection; async projection.

## Decisions

**Redaction is the crux, not an afterthought.** A network Event carries the user's
IP and the full URL path. `src_ip`/`src_port` are user-identifying and the Event
already carries a pseudonymous Subject (D23), so they are CLEARED. `http_path`
(path + query) routinely carries tokens, emails and search terms — content-like, so
it is CLEARED (D10/D29: content and content-like data may not cross). What is KEPT
is the DESTINATION (`dst_ip`/`port`, `sni_host`), `http_method`, `protocol`,
`direction`, `flow_id` — enough for the fleet view to say "someone tried to POST to
upload.evil.com and it was blocked" without the user's IP or the sensitive path.
The Decision is projected as-is (already schema-guarded to carry no content, URL, or
detector internals, D14).

**Projection is opt-in, additive, and best-effort.** The local forward-secure
ledger is the system of record (D30); telemetry is a VIEW. `SetTelemetry(nil)` (the
default) projects nothing. A projection error is logged and swallowed — the request
is not failed, because the decision is already durably recorded locally and the
publisher offline-queues (D67). Losing a telemetry copy degrades the fleet view, not
the audit trail.

**Reuse `core.Transport`, no new transport.** The gateway holds a
`core.Transport`; the cmd wires a `SignedPublisher` (identity + NATS conn) exactly as
the fleet agent does. The gateway does not import the NATS package — it depends on
the `core.Transport` interface, so the layering and the parser-free dependency graph
(D72) are unchanged.

## Risks / Trade-offs

- **The kept destination is still monitoring data.** "Which sites the fleet talks
  to" is surveillance-adjacent; it is the point of a security fleet view, opt-in,
  and subject to the notice/DPIA posture the project documents. Redacting the user
  IP and URL path is the boundary-safety line, not a claim that the projection is
  privacy-neutral.
- **Host-level only loses URL context.** An operator investigating an incident may
  want the full URL; that is a deliberate, policy-gated escalation, noted, not the
  default.
- **Synchronous best-effort adds a publish per decision.** The publisher enqueues
  locally (D67), so it is cheap; async projection is a noted option.
