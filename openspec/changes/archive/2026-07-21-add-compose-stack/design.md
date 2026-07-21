## Context

The binaries exist (`cmd/openshield-server` reads OPENSHIELD_DSN + OPENSHIELD_NATS_URL and migrates
on boot). Postgres and NATS have official images. Podman rootless is the container runtime (not
Docker). The plan's verification assumes `podman compose up`.

## Goals / Non-Goals

**Goals:**
- One command (`podman compose up`) from a clean checkout → Postgres + NATS + control plane running.
- Server waits for Postgres health before starting; migrations run on boot (no separate step).
- Rootless-friendly; dev credentials; clearly not production.

**Non-Goals:**
- Production hardening (TLS, secrets, tuning, NATS persistence); an agent in the network; a CI
  live-stack job.

## Decisions

### compose.yaml services
- `postgres`: official postgres:16, env for the openshield db/user/pw, a healthcheck
  (`pg_isready`), a named volume for data.
- `nats`: official nats:2 image, default config, the client port exposed on the network.
- `server`: built from `Containerfile`, `depends_on` postgres (condition: service_healthy),
  env `OPENSHIELD_DSN` pointing at the `postgres` service and `OPENSHIELD_NATS_URL` at `nats`.

Ports: Postgres and NATS bound to localhost for convenience; the server needs no inbound port (it
connects out to NATS and Postgres). Documented that production would not expose the DB.

### Containerfile: multi-stage, minimal, rootless
Stage 1 (`golang:1.26`): copy the module, `go build` the server. Stage 2 (a minimal base):
copy the binary, run as a non-root user. No CGO. The image builds the server ONLY; the other
binaries (agent/worker/ctl) are not containerised (the agent needs host access a container lacks).

### Migrations on boot, not a separate step
The server already runs `postgres.Migrate` on start, so the stack is self-migrating — there is no
migration step for a contributor to forget. The healthcheck gate ensures Postgres is ready before
the server tries.

### Verification is a documented smoke test
`podman compose up` is validated by hand (build the image, bring the stack up, confirm the server
logs "subscribing to telemetry" and stays up). Not a CI job — spinning containers in CI is a
separate infra decision, and CI already covers the code with a Postgres service + embedded NATS.

## Risks / Trade-offs

- **Dev-only, plaintext credentials.** Appropriate for local dev, dangerous anywhere else; stated
  in comments and the proposal. Production is a separate packaging concern (T-027).
- **`podman compose` delegates to docker-compose** in this environment. The compose file uses the
  common subset both understand, so it works under either.
- **First build is slow** (compiles the module + deps in the image). Acceptable for a one-time dev
  setup; a build cache mitigates repeats.
- **No agent in the stack.** The agent needs fanotify/host access a container does not have;
  running it is a documented host-side step, not part of compose.
