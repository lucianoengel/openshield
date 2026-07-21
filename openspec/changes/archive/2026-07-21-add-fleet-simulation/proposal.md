# Add the multi-agent fleet simulation in podman (Direction 1)

## Why

Identity, enrollment, signed telemetry, heartbeat, dead-man's-switch and revocation all exist and
are unit-tested, but never together, and never at fleet scale across real containers. The endpoint
got a walking skeleton; the FLEET has never been demonstrated as a running whole — multiple agents,
each with its own identity, enrolling, publishing verified telemetry, and one of them going dark or
being revoked. Fanotify permission mode is not simulable in rootless podman (probed: it needs
init-namespace CAP_SYS_ADMIN), but the fleet path needs no special kernel privilege — it is pure
processes and networking, and IS simulable. This builds that simulation.

## What changes

**A minimal fleet agent (`cmd/openshield-fleet-agent`) and its container image.** It generates a
per-agent identity, enrolls over HTTP (`POST /enroll` with a token, D51), then publishes SIGNED
telemetry and heartbeats (D50) on an interval. It is the fleet-facing half of an agent — it does
NOT parse files or run the pipeline (that is the engine); it exists to exercise identity → enroll →
signed telemetry → heartbeat end to end.

**An operator-local token issuance command.** `openshield-server issue-token [ttl]` connects to
Postgres and issues a single-use token, printing it — the ADMIN side of enrollment (issuance is not
a network endpoint, D51). The fleet script runs it inside the control-plane container to mint one
token per agent.

**A fleet demo + assertions (`deploy/fleet-e2e.sh`).** It brings up the control plane (with the
enrollment endpoint), mints a token per agent, starts N agent containers on the shared network,
and then ASSERTS the fleet properties against the real control plane: each agent's telemetry
arrives VERIFIED and attributed; each is seen (last-seen advances); killing one makes it OVERDUE on
the dead-man's-switch; revoking one makes its subsequent telemetry REJECTED. It tears down and
restores the dev database, on any exit.

## What this does NOT claim or cover

- **It is not the fanotify/endpoint path.** The fleet agent publishes telemetry directly; it does
  not classify files (that is the engine). Fanotify permission mode is not available in rootless
  podman (probed) and stays a real-root concern. The fleet simulation proves the fleet CONTROL path
  (identity, enroll, verified telemetry, liveness, revocation), not kernel eventing.
- **No TLS on enrollment.** HTTP, as D51 states; production fronts it with TLS. The demo is a dev
  simulation, not a hardened deployment.
- **It is not a load/scale test.** A handful of agents proving the properties, not thousands
  proving throughput. Stated.
- **Not a CI job by default.** It builds images and runs containers; it runs on demand via the
  script, like the compose smoke test and the container e2e.

## Decisions

Depends on **D44** (identity), **D50** (signed telemetry), **D51** (enrollment endpoint), **D42**
(dead-man's-switch), **T-023** (control plane), **T-025** (compose), and the probed fact that
rootless podman cannot do fanotify permission mode.

No new architectural decision — it demonstrates the existing fleet decisions together. It records
that the fleet simulation is `deploy/fleet-e2e.sh`, that token issuance is an operator-local command
(`openshield-server issue-token`), and that the fleet control path is simulable in podman while the
fanotify path is not.
