## Context

compose.yaml exposes NATS on 127.0.0.1:4222 and Postgres on 127.0.0.1:55432; the server container
connects out to `nats:4222` and `postgres:5432` on the internal network and has no exposed port.
So a host client reaches NATS and Postgres directly, while the server (subscribed) does the
persistence. The dev `openshield-pg` container (unit tests) also uses 55432, so the e2e must free
it first and restore it after.

## Goals / Non-Goals

**Goals:**
- Drive the RUNNING containerised server binary: publish telemetry over real NATS, verify it lands
  in real Postgres.
- One idempotent script: up → wait → test → down → restore dev Postgres.

**Non-Goals:**
- The agent fanotify path (no host access in a container); enrollment over the wire (no endpoint);
  a default CI job.

## Decisions

### Build-tagged Go test, driven from the host
`e2e/e2e_test.go` with `//go:build e2e` so it is invisible to `go test ./...`. It reads
`OPENSHIELD_E2E_NATS` (default nats://127.0.0.1:4222) and `OPENSHIELD_E2E_DSN` (default the exposed
Postgres), publishes an Event + ClassificationSummary + Decision via `nats.Transport` (the same
client the agent uses), then polls `fleet_telemetry` for the event id until 3 rows appear or a
timeout — the timeout being the honest failure (the server did not persist).

A unique event id per run (from an env var the script sets, since Go test cannot use the clock/rand
freely) keeps runs independent without a DB wipe.

### deploy/e2e.sh orchestrates
1. Stop `openshield-pg` (free 55432).
2. `podman-compose up -d --build`.
3. Wait until the server logs "subscribing to telemetry" (bounded poll).
4. `OPENSHIELD_E2E_EVENT=e2e-<pid> go test -tags e2e ./e2e/...`.
5. `podman-compose down`; `podman start openshield-pg`.
Steps 4's result is the script's exit code; teardown runs regardless (trap).

### Why poll, not sleep
The server persists asynchronously after receiving the NATS message; a fixed sleep is flaky. The
test polls with a deadline — passes as soon as the rows land, fails loudly if they never do.

## Risks / Trade-offs

- **Port contention with the dev Postgres.** The script frees and restores `openshield-pg`; running
  it while unit tests run against 55432 would clash, so it is a standalone command, not concurrent.
- **Build time.** First `--build` compiles the server image; subsequent runs are cached. Acceptable
  for an on-demand e2e.
- **Not CI by default.** Container e2e in CI is a separate decision; the script makes a human run
  trivial and CI can adopt it later.
- **Covers the telemetry path only.** The agent fanotify path and enrollment-over-wire are out of
  scope and stated; this closes the "does the real binary persist real telemetry" gap specifically.
