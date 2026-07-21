# Add the podman compose dev stack (T-025)

## Why

The plan's own end-to-end verification section opens with `podman compose up` bringing up Postgres
+ the control plane, and no ticket built it. A contributor cloning the repo has no single command
to get a running stack; they must hand-start Postgres, NATS, run migrations, and launch the
server. That friction is exactly what kills adoption of a self-hostable tool, and it makes the
project's own verification steps unrunnable.

## What changes

**A `compose.yaml` that brings up the full backend from a clean checkout with one command.**
Postgres + NATS + the control plane (`openshield-server`), wired together, with the server waiting
for Postgres to be healthy before it starts. `podman compose up` from a fresh clone yields a
running stack with no manual steps — migrations run on server start (the control plane migrates on
boot), so there is no separate migration step to forget.

**A `Containerfile` for the server built from the repo.** Multi-stage: build the Go binary, then a
minimal runtime image. Rootless-friendly (Podman, not Docker — D-none, the environment
constraint), no root inside the container.

**Configuration by environment, matching the binaries' existing env vars.** The server already
reads `OPENSHIELD_DSN` and `OPENSHIELD_NATS_URL`; compose sets them to the in-network service
addresses. No config files to edit for the dev path.

## What this does NOT claim or cover

- **It is a DEV stack, not a production deployment.** Default credentials (`openshield`/`dev`), no
  TLS, no resource limits tuned for load, NATS without persistence. A production deploy hardens all
  of this; the compose file says so in comments and is not represented as production-ready.
- **It does not include an agent.** The agent runs on an endpoint, not in the compose network —
  the stack is the control-plane backend the agent connects TO. Bringing up an agent against it is
  a separate manual step (documented), because an agent needs host access (fanotify) a container
  does not have.
- **It does not run in CI as a live stack.** CI tests the code with a Postgres service and an
  embedded NATS; validating `podman compose up` end to end is a documented manual smoke test, not a
  CI job, because spinning containers in CI is a separate infrastructure decision.
- **No secrets management.** Dev credentials are in the compose file in plaintext, appropriate for
  a local dev stack and nowhere else. Stated.

## Decisions

Depends on **T-023** (the control plane the stack runs), **D24** (NATS is the agent↔control-plane
boundary), and the environment constraint that containers are **Podman rootless, not Docker**.

No new architectural decision — this is dev infrastructure. It records the operational fact that
the dev stack is `podman compose up`, brings up Postgres + NATS + control plane, and is explicitly
not a production deployment.
