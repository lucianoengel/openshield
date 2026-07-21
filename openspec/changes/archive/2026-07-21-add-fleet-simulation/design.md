## Context

The control plane serves NATS telemetry + `POST /enroll` (D51) and verifies signed telemetry (D50)
and heartbeats (D42). `SignedPublisher` signs telemetry; identity generates keypairs. No agent
binary publishes to the fleet; token issuance has no operator command. compose.yaml brings up the
backend. Probed: fanotify permission mode fails in rootless podman even --privileged.

## Goals / Non-Goals

**Goals:**
- A fleet agent that enrols over HTTP then publishes signed telemetry + heartbeats.
- An operator-local `issue-token` command.
- A demo script asserting: verified+attributed telemetry, last-seen, dead-man's-switch on a killed
  agent, revocation rejecting telemetry — across real containers.

**Non-Goals:**
- Fanotify/pipeline (not simulable / different concern); TLS; scale; a CI job.

## Decisions

### cmd/openshield-fleet-agent
Env: `OPENSHIELD_AGENT_ID`, `OPENSHIELD_ENROLL_URL`, `OPENSHIELD_ENROLL_TOKEN`, `OPENSHIELD_NATS_URL`,
`OPENSHIELD_HEARTBEAT` (interval). It: generates an identity; POSTs `/enroll` with the token +
base64 public key; on success connects to NATS and, on the interval, publishes a signed Heartbeat
and one signed Event (so both last-seen and verified telemetry are exercised). A signed publisher
for the Heartbeat is added (the current SignedPublisher covers Event/Classification/Decision; extend
it with PublishHeartbeat wrapped in a SignedTelemetry of kind "heartbeat", verified on ingest).

### issue-token operator command
`openshield-server issue-token [ttlSeconds]`: connect to Postgres (OPENSHIELD_DSN), migrate if
needed, `IssueToken`, print the token to stdout. This is the ADMIN side (direct DB access = operator
trust); it is not the network endpoint. The fleet script runs it via `podman exec` in the control-
plane container.

### deploy/fleet-e2e.sh
1. Free the port; `podman-compose up -d --build` with the enrollment endpoint enabled
   (OPENSHIELD_HTTP_ADDR on the server) and the server's HTTP port published.
2. Build the fleet-agent image.
3. For each of N agents: `podman exec server openshield-server issue-token` → a token; run an
   agent container with that token on the compose network.
4. Poll the control plane (via a build-tagged Go checker or SQL over the published Postgres port)
   for: N agents with VERIFIED telemetry attributed; all seen recently.
5. Kill one agent container; assert it becomes OVERDUE (dead-man's-switch) after the threshold.
6. Revoke one agent (via an operator command `openshield-server revoke <id>`); assert its next
   signed telemetry is REJECTED (RejectedTelemetry rises / no new verified rows for it).
7. Teardown + restore dev Postgres via trap.

Assertions run as a build-tagged Go program (`fleet` tag) querying the published Postgres + the
control-plane state, or as SQL — whichever is simplest and reliable.

## Risks / Trade-offs

- **Container orchestration flakiness.** The script polls with deadlines (not sleeps) and tears down
  on any exit; a handful of agents keeps it fast and reliable.
- **Revocation assertion timing.** After revoke, the agent keeps publishing; the control plane
  rejects. The script waits for RejectedTelemetry to rise for that agent.
- **issue-token via podman exec** couples the script to the container name; documented.
- **Not CI.** On-demand, like the other container demos. Stated.
