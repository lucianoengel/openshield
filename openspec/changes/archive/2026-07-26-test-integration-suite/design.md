## Context

1023 package tests, zero that run the product. `deploy/` has four shell e2e scripts, none referenced by
`make all`, and one of them fails on this machine for an environmental reason.

## Goals / Non-Goals

**Goals:** a harness that runs real binaries against real infrastructure; robustness on a busy machine;
diagnosable failures; a first batch of scenarios; skip-not-fail without podman.

**Non-Goals (this change):** the full scenario set; porting or deleting the shell scripts; CI wiring.

## Decisions

### Ephemeral ports, because the alternative is demonstrably how these rot

`deploy/e2e.sh` stops the dev Postgres to free 55432 and does nothing about 4222, so it dies on
`bind: address already in use`. That is not a hypothetical — it is what happened when I ran it. The failure
looks like a broken product, costs someone an afternoon, and the script quietly stops being run.

Every container here binds `127.0.0.1::<port>` and the harness asks podman which port it got.

### Real subprocesses, not in-process construction

Constructing a `controlplane.Server` in the test would be a larger package test. Running the built binary
is the only thing that proves `main()` reads the setting, starts the loop and registers the subscription —
which is the gap this exists to close.

### Wait on effects, never on sleeps

Readiness is a log line or an observable database change. A sleep long enough to be reliable under load
makes the suite slow; short enough to be fast makes it flaky; and a flaky integration suite is worse than
none because it trains people to re-run rather than read.

A listening socket is also not a ready database — Postgres accepts connections before it will serve
queries, so readiness is `pg_isready`, not a TCP dial.

### Build the binaries once

Twelve commands per scenario would dominate runtime and discourage adding scenarios, which is how a suite
stops growing. One build, shared, in a temp dir.

## Risks / Trade-offs

- **Container startup costs seconds per scenario** → the stack is per-test for isolation; if the suite
  grows enough that this hurts, sharing a stack across a group is the next step, at the cost of
  cross-test coupling.
- **It cannot run where podman is absent** → it skips, so the gate is unaffected.
- **It is not yet broad** → stated in the proposal rather than implied by the existence of a suite.

## Migration Plan

Additive; no production code changes.

## Open Questions

- Whether the `deploy/*.sh` scripts should be ported into this suite or deleted once it covers their
  ground — they should not simply be left unreferenced and rotting, which is the state this found them in.
