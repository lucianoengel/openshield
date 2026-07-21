## Context

The pieces exist and are individually tested: `fanotify.Open(dir)` →
`w.Next(ctx)` yields a `*corev1.Event` (D52, unprivileged notify mode);
`engine.New(worker, policy, ledger, log, deadline)` assembles classify→policy→
decide→audit; `engine.Process(ctx, ev)` runs one event. `TestFanotifyToAudit`
already wires exactly this loop in a test. What is missing is that same loop in
`cmd/openshield-engine/main.go`, which today builds `eng` and throws it away.

## Goals / Non-Goals

**Goals:**
- The shipped `openshield-engine` binary runs the observe path against real
  directories.
- Prove it as a BINARY (build + run the actual commands), not via internal
  packages.
- Make the docs true: observe path ships as a binary; inline blocking is deferred.

**Non-Goals:**
- Inline blocking or the privileged permission-mode agent (D49 — deferred, and
  notify mode cannot block anyway).
- Registering enforcers by default (observe-only stays the default, D1).
- The agent→engine IPC / privilege-split wiring — unnecessary for observe-only,
  since notify-mode fanotify needs no privilege (D52). That IPC belongs to the
  Phase-2 inline agent.

## Decisions

**The engine self-watches in notify mode; no privileged agent for observe.** D48
introduced a privileged fanotify agent because PERMISSION mode (blocking) needs
`CAP_SYS_ADMIN`. But D52 proved NOTIFY mode (observe) works unprivileged. So for
the observe product the engine opens the connector directly — one unprivileged
process holding OPA+pgx (D48) and the notify-mode watcher. The privileged agent
is a Phase-2 concern for inline blocking only; wiring an agent→engine IPC now
would be building plumbing for a mode that does not exist yet.

**Watch dirs are explicit config, not a default sweep.** `OPENSHIELD_WATCH_DIRS`
is a comma-separated list; the engine refuses to start with none (an engine
watching nothing is a silent no-op, the failure D17 forbids in spirit). Each dir
gets its own watcher; events from all are processed by the one pipeline.

**One watcher goroutine per dir, funnelling to a single Process loop.** Each
watcher's `Next` blocks; a small fan-in over a channel feeds `engine.Process`
serially (the pipeline is synchronous, D24). A `Next` error that is not context
cancellation is logged and the watcher continues — a transient read error must
not silently stop observation.

**Binary-level proof.** The e2e builds `openshield-engine` and
`openshield-worker` with `go build`, starts the engine process with
`OPENSHIELD_WATCH_DIRS` pointed at a temp dir and `OPENSHIELD_DSN` at the test
Postgres, writes a file containing a valid CPF into the watched dir, and polls
the ledger (via `openshieldctl` or a direct query) for an ALERT entry. This
exercises the SHIPPED artifact — process boundaries, env config, the worker
subprocess, the real ledger — which package tests cannot.

**Agent stub tells the truth.** `openshield-agent`'s message changes from
"not implemented" to naming itself the deferred privileged permission-mode
(inline-blocking) component (D49), pointing operators to `openshield-engine` for
the observe path. It exits non-zero so a systemd unit does not treat a stub as a
healthy service.

## Risks / Trade-offs

- **Notify mode cannot block.** The running product observes and records; it does
  not prevent. That is exactly D1/D49's honest position, now reflected in what the
  binary actually does. The risk is a reader assuming "runs" means "blocks"; the
  docs must say observe-only explicitly.
- **fanotify notify-mode coverage is per-directory, not recursive.** A watch dir
  covers its direct entries (D52's empirical finding: path = watchedDir/name).
  Recursive/mount-wide watching is a later connector concern; documented, not
  silently assumed.
- **The binary e2e needs Postgres + build tooling**, so it is a heavier test. It
  runs behind the same `OPENSHIELD_REQUIRE_POSTGRES` gate and LOUD-skips
  otherwise, consistent with the other integration tests — but a green CI run
  must actually exercise it.
- **Root is still not required to observe** (D52) and still defeats the agent's
  integrity if present (D16) — unchanged.
