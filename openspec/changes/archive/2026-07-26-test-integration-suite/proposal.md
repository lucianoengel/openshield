## Why

1023 tests, and none of them run the product. Every one tests a package, which leaves a specific and
dangerous gap: the wiring in `cmd/` — which environment variable reaches which constructor, which loop
starts under the leader, which subscription is registered — is exercised by **nothing**. Those are exactly
the defects that survive to a deployment, because every unit involved passes on its own.

There *are* four end-to-end shell scripts in `deploy/`. They are **not in `make all`**, and running one on
this machine showed why that matters: it fails with `bind: address already in use` because it hardcodes
port 4222 and a development NATS container holds it. It frees Postgres's port and not NATS's. A test that
fails because the machine is busy reads as a broken test, and a test that reads as broken stops being run.

## What Changes

- `test/integration`: a Go harness that starts Postgres and NATS in containers, builds the real binaries,
  runs them as subprocesses, and asserts on what crosses the boundaries between them.
- **Ephemeral ports and per-run container names**, which is the fix for the failure above: every container
  takes a kernel-assigned port the harness discovers, so the suite never collides with a busy machine and
  a crashed run never poisons the next.
- **Subprocess output captured and dumped on failure** — an integration failure whose cause is in a
  subprocess's stderr, with the stderr discarded, is a failure nobody can diagnose.
- Readiness is waited on by **observable effect or log line**, never a fixed sleep: a sleep long enough to
  be reliable on a loaded machine makes the suite slow, and one short enough to be fast makes it flaky.
- First scenarios: the binary migrates a fresh database; a malformed **bootstrap** setting stops the boot;
  a **dynamic** setting in the environment is ignored and reported; the `config` subcommand reports origins
  and never prints a secret.

## Capabilities

### Modified Capabilities
- `e2e-verification`: adds a real-process integration suite covering the `cmd/` wiring no package test reaches.

## Impact

- **New**: `test/integration`. No production code changes.
- It runs inside `make all` and **skips without podman**, so the gate stays green on a machine that lacks it.
- **Honest scope**: this is the FOUNDATION plus a first batch. The scenarios that matter most —
  enrollment → signed telemetry → correlation → incident → playbook, coordinated response across gateway
  and endpoint, fleet disable and its acknowledgement, config revisions applying live across processes —
  are not written yet. The existing `deploy/*.sh` scripts are left in place and still unreferenced by the
  gate; whether they are ported or deleted is a follow-up, not something to decide by leaving them to rot.
