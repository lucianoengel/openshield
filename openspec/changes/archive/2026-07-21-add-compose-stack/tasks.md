## 1. Containerfile

- [x] 1.1 `Containerfile`: multi-stage (golang build → minimal runtime), builds `openshield-server`,
      runs as non-root, no CGO

## 2. compose

- [x] 2.1 `compose.yaml`: postgres (with pg_isready healthcheck + named volume), nats, server
      (depends_on postgres service_healthy), env OPENSHIELD_DSN/OPENSHIELD_NATS_URL wired to the
      services
- [x] 2.2 Dev credentials + no-TLS + not-production stated in comments; production pointed to T-027

## 3. Verify + docs

- [x] 3.1 Build the server image and bring the stack up (`podman compose up -d`); confirm the server
      logs "subscribing to telemetry" and stays up; tear down. Record the smoke test
- [x] 3.2 README/docs: the dev stack is `podman compose up`; state dev-only
- [x] 3.3 Mark T-025 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

Smoke-tested for real: `podman build` produced the server image, then
`podman-compose up -d` brought up Postgres (healthy), NATS, and the server. The
server logged **"subscribing to telemetry on nats://nats:4222"** and stayed up —
migrations ran on boot, no manual step. Torn down cleanly with `podman-compose
down`.

**Tool note:** use `podman-compose` (the native Python tool), NOT `podman
compose`, which shells out to docker-compose and needs a Docker daemon socket
rootless Podman does not provide. Recorded in `compose.yaml`.

Not a CI job — spinning containers in CI is a separate infra decision, and CI
already covers the code with a Postgres service + embedded NATS.
