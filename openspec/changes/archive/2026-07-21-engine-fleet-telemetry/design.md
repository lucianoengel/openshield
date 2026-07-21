## Context

The gateway (D77) projects a boundary-safe view of its decisions to the control
plane via `core.Transport`/`SignedPublisher`, wired in its binary with the shared
`enroll` helper. The engine has the identical shape — `Process` produces a Decision
recorded via the audit sink — but its binary imports no transport at all. The
control plane is fully built to ingest and verify Events/Decisions (D41/D44); it has
simply never received a real one from an endpoint.

## Goals / Non-Goals

**Goals:**
- Real endpoint detections reach the verified fleet stream.
- Reuse the gateway's proven telemetry pattern exactly.
- Keep the single-host observe-only default unchanged (projection is opt-in).

**Non-Goals:**
- Retiring the fleet-agent simulator; path redaction; ClassificationSummary
  projection.

## Decisions

**Mirror the gateway telemetry (D77), do not reinvent.** The engine gets an optional
`Projector` (PublishEvent + PublishDecision), `SetTelemetry`, and a best-effort
projection in `Process` after the local record — the same code shape the gateway
uses, so the two data planes reach the control plane the same way. The interface is
defined engine-local (not imported from `gateway`) to keep endpoint and network
layers from depending on each other; the 2-method duplication is trivial and both
are satisfied by `SignedPublisher`.

**Project the Event AS-IS — the file path is identity, not content.** The gateway
redacted the URL `http_path` because a path+query carries tokens and search terms
(content-like). A file path is the FILE's identifier — the fleet investigation needs
"which file on which endpoint" — and the Subject is already pseudonymous (D23), so
there is no user identifier to drop. The Event crosses as-is; the Decision is already
schema-guarded to carry no content (D14). Path redaction (for deployers who consider
the path itself sensitive) is a noted configurable follow-up, not the default.

**Best-effort, additive, opt-in — the local ledger stays the system of record.** A
projection failure is logged, never fails `Process`: the decision is already durably
recorded in the local forward-secure ledger (D30) and the publisher offline-queues
(D67), so a lost telemetry copy degrades the fleet VIEW, not the audit trail. With no
projector configured (the default), the engine behaves exactly as before — the
single-host path is untouched.

**The binary wiring is the gateway's, verbatim.** `cmd/openshield-engine` builds the
SignedPublisher from an enrolled identity + NATS conn (optional seq file) when
`OPENSHIELD_NATS_URL` + `OPENSHIELD_ENROLL_URL` are set, and `SetTelemetry`s the
engine. This is the same wiring `cmd/openshield-gateway` already has, using the same
shared `enroll` helper.

## Risks / Trade-offs

- **The fleet now sees real file paths and pseudonymous subjects** — this is
  employee-monitoring data crossing to the server, subject to the notice/DPIA posture
  the project documents. It is opt-in and the subject is pseudonymous; the path is
  the investigation's point. Stated, not hidden.
- **Enrollment is required** — the engine must enroll an identity like any telemetry
  producer (D44); without it the control plane rejects the stream. The wiring makes
  projection contingent on both NATS and enrollment being configured.
