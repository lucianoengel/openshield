## Context

Binaries: openshield-agent (privileged fanotify), openshield-worker (unprivileged parser),
openshield-server (control plane). deploy/ has drop-ins referencing base units that don't exist.
systemd-analyze verify is available to validate units. The worker self-applies seccomp (T-012);
cgroup limits are the existing drop-in.

## Goals / Non-Goals

**Goals:**
- Base systemd units that enact the privilege split (agent: CAP_SYS_ADMIN only; worker:
  unprivileged user + hardening; server: ordinary service).
- An idempotent install script and a documented, watchdog-safe upgrade path.
- Unit correctness machine-checked with systemd-analyze verify.

**Non-Goals:**
- Distro packages / signed artifacts; a CI install-run job; new hardening; secrets/TLS; non-systemd
  init.

## Decisions

### The units encode least privilege
- `openshield-agent.service`: `User=root`, `AmbientCapabilities=CAP_SYS_ADMIN`,
  `CapabilityBoundingSet=CAP_SYS_ADMIN` — root for fanotify, but only that one capability, not the
  full root set. `NoNewPrivileges` is NOT set on the agent (it needs to spawn the worker), but the
  bounding set caps what it and its children can gain.
- `openshield-worker.service`: `User=openshield-worker` (a dedicated non-login system user),
  `CapabilityBoundingSet=` (empty — no capabilities), plus the hardening drop-in (PrivateNetwork,
  MemoryMax, seccomp is in-process). This is the parsing containment (D35).
- `openshield-server.service`: `User=openshield`, `After=network-online.target`, reads
  OPENSHIELD_DSN/OPENSHIELD_NATS_URL, restart on-failure.

The drop-in filenames in deploy/ use `.d-` as a flat naming convention; install.sh places them into
the real `.service.d/` directories.

### install.sh: idempotent, from built tree to enabled services
Steps, each idempotent: install binaries to /usr/local/bin; create the openshield and
openshield-worker system users if absent; install unit files and drop-ins; `systemctl daemon-reload`;
enable (not necessarily start) the services. Re-running it is a no-op-to-update, not a duplicate.
The script refuses to run without root (installing units needs it) with a clear message, and does
NOT start the agent automatically (fanotify on an unconfigured host is the operator's call).

### Upgrade is watchdog-safe
Documented: build, `install.sh` (replaces binaries + units), `systemctl restart openshield-agent`.
The restart is safe under load because the fail-open watchdog (D18) answers the kernel regardless of
the pipeline's state — a permission event during the restart window fails open, audited, rather than
hanging the process. This is why D18 was built even though Phase 1 does not enforce: it is what
makes a routine upgrade not a machine-hang risk.

### Validation
`systemd-analyze verify` on each unit in the change's verification, so a malformed directive fails
in review. A full install-start-upgrade cycle is a documented manual smoke test (needs a systemd
host + root), the same honest boundary as the compose stack's `podman-compose up`.

## Risks / Trade-offs

- **Can't fully test install in this environment** (no systemd session as this user, no root). Units
  are syntax-verified; the install/run cycle is a documented smoke test. Stated, not hidden.
- **CAP_SYS_ADMIN is broad.** It is what fanotify permission events require; the bounding set limits
  the agent to exactly it, which is the least privilege the kernel API allows. Noted.
- **The worker unit assumes the agent connects to a systemd-managed worker**, while the dev code
  spawns the worker as a subprocess. The unit expresses the production shape (T-006's comment); the
  agent's connect-vs-spawn wiring for production is a follow-up, flagged.
- **No distro package.** install.sh is the floor; .deb/.rpm is release engineering, deferred.
