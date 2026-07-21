## Context

`install.sh` builds `openshield-engine` (added in D64's change) but installs no
unit or user for it; it creates `openshield` and `openshield-worker` users and
installs the agent/worker/server units. The engine is unprivileged (D52 notify
mode) but holds the signer key (D46, 0600) and OPA. The worker unit is the
isolation pattern to mirror (dedicated user, empty caps, NoNewPrivileges).

## Goals / Non-Goals

**Goals:**
- The engine runs under a dedicated user, never the monitored account or root.
- The signer state is owned by that user, in a directory only it can write.
- Anchoring actually runs (its units installed).
- A test fails the build if the isolation regresses.

**Non-Goals:**
- Defending against host root (D16) — out of scope by design.
- A full seccomp profile for the engine (it needs the network for pgx and OPA;
  the worker is the seccomp-network-deny process, D35) — the engine's isolation is
  user + filesystem + caps, not syscall filtering.
- Auto-starting the engine with watch dirs — the operator configures WATCH_DIRS.

## Decisions

**A dedicated `openshield-engine` user, mirroring the worker.** `ensure_user
openshield-engine` (idempotent). The unit sets `User=`/`Group=openshield-engine`,
`CapabilityBoundingSet=` (empty), `NoNewPrivileges=true`, `ProtectSystem=strict`,
`PrivateTmp=true`, `ProtectHome=true`. It needs the network (pgx to Postgres) and
read access to the watched dirs, so it is not seccomp-network-denied (that is the
worker's role, D35).

**`StateDirectory=openshield-engine` for the signer.** systemd creates
`/var/lib/openshield-engine` owned by the engine user, 0700. The unit points
`OPENSHIELD_SIGNER_FILE` there, so the signer state (D46) is owned by the engine
user and unreadable by the monitored account. This is the concrete isolation win:
the key that signs the evidence is not under the account whose activity is the
evidence.

**Env as commented defaults.** `OPENSHIELD_WATCH_DIRS` has no safe default (an
engine watching nothing refuses to start, D62), so the unit ships it commented
with guidance; `DSN`/`WORKER_BIN`/`SIGNER_FILE` have sensible defaults the
operator overrides. The engine is enabled but the operator sets WATCH_DIRS before
it will run.

**A build-time isolation guard.** A Go test parses `deploy/systemd/openshield-
engine.service` and `deploy/install.sh` and asserts: `User=openshield-engine`
(not root, not `openshield`/agent/monitored); `NoNewPrivileges=true`; no
`CapabilityBoundingSet` granting `CAP_SYS_ADMIN` or `~`(all); and that
`install.sh` creates the engine user and installs the engine + anchor units. A
regression (dropping User=, widening caps, forgetting the install) fails the test.

## Risks / Trade-offs

- **The engine still has network + DB access.** It must (pgx, OPA). That is a
  larger surface than the worker's, but the engine does NOT parse attacker bytes
  (the worker does, D29) — so the network access is to Postgres, not to
  attacker-controlled input. Stated, not hidden.
- **Host root defeats it (D16).** A dedicated user stops the wrong-account
  erosion, not a root compromise; the guarantee is scoped honestly.
- **Operator must set WATCH_DIRS.** The engine will not observe until configured;
  a safe default is impossible (watching the wrong thing is worse than watching
  nothing). Documented in the unit.
