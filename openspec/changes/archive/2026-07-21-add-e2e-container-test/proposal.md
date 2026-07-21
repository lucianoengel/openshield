# Add a real container end-to-end test (T-023 e2e)

## Why

The control-plane tests prove the `Server` struct works in-process against a real Postgres and an
EMBEDDED (in-process) NATS. What has never been exercised is the actual `openshield-server`
BINARY, running in a container, talking to a real NATS container and a real Postgres container,
with telemetry crossing the real wire. The compose smoke test confirmed the stack comes UP; it did
not push telemetry through and confirm it LANDS. That gap is exactly where container/networking/
config bugs hide — a wrong DSN, a subject mismatch, a binary that logs "ready" but never persists.

## What changes

**A build-tagged e2e test that drives the running stack from outside.** Tagged `e2e` so it never
runs in the normal suite, it connects to the compose-exposed NATS and Postgres ports, publishes an
Event + ClassificationSummary + Decision through the real `nats.Transport`, and polls the Postgres
container's `fleet_telemetry` until all three land — proving the containerised server binary
received them off real NATS and persisted them to real Postgres.

**An orchestration script (`deploy/e2e.sh`).** Idempotent: it frees the port, brings the stack up
with `podman-compose` (building the server image), waits for the server to be subscribed, runs the
tagged test, reports pass/fail, and tears the stack down — restoring the dev Postgres the unit
tests use. One command, clean before and after.

## What this does NOT claim or cover

- **It is not the agent's fanotify path end to end.** The agent needs host access (fanotify) a
  container lacks, so the "agent" side of this e2e is a telemetry client using the same transport
  the agent uses — it proves the agent→control-plane→store path, not the kernel-event→agent path
  (which the agent unit tests and the fanotify spike cover).
- **It does not exercise enrollment/identity over the wire.** The server binary exposes no network
  enrollment API yet (Enroll is an in-process method); the e2e covers the telemetry path T-023
  actually serves. Identity over the wire is a follow-up when an enrollment endpoint exists.
- **It is not a CI job by default.** It needs a container runtime and builds an image; it runs on
  demand via `deploy/e2e.sh`. Wiring it into CI is a separate infra decision (like the compose
  smoke test).
- **It does not test the CLI reading fleet telemetry.** The CLI queries the audit ledger, not the
  fleet aggregate; the e2e verifies persistence directly in Postgres, which is the T-023 acceptance
  ("telemetry lands in Postgres").

## Decisions

Depends on **T-023** (the control plane), **T-025** (the compose stack it brings up), **D24** (the
NATS boundary and its subjects), and the environment fact that `podman-compose` (not `podman
compose`) is the tool.

No new architectural decision — this is a verification capability. It records that the container
e2e is `deploy/e2e.sh` and proves the real server binary persists telemetry off real NATS.
