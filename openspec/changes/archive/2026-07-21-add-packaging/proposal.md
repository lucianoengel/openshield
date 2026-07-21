# Add packaging: systemd units + install/upgrade path (T-027)

## Why

Every hardening decision this project made — the privilege split (D13/D29), the unprivileged
sandboxed worker (D35), the fail-open watchdog surviving a restart (D18) — assumes a real
deployment shape, and none of it is expressed as installable units. The `deploy/` directory has
drop-ins (worker hardening, the stop hook) that reference base units that do not exist. Without
packaging, the privilege split is a code fact that a deployer has to reconstruct by hand, which is
exactly how a privilege boundary erodes: the agent ends up running everything as root because
nobody wrote the unit that says otherwise.

## What changes

**systemd units that ENACT the architecture, not just run binaries.**
- `openshield-agent.service`: the privileged half. Runs as root with ONLY `CAP_SYS_ADMIN` (ambient,
  not full root capabilities), for fanotify — the minimum the privileged process needs, and nothing
  more. It never parses attacker bytes (D29).
- `openshield-worker.service`: the unprivileged half. Runs as a dedicated non-login user, with the
  existing hardening drop-in (seccomp via the in-process filter, no network, cgroup limits, D35).
  This is where parsing happens, contained.
- `openshield-server.service`: the control plane. An ordinary network service, no special
  privilege, `depends`-ordered after its database.

The units carry the security posture in configuration a deployer inherits by default — the split is
enforced by the unit files, not by a deployer remembering to drop capabilities.

**An install script and a documented upgrade path.** `deploy/install.sh` (idempotent) installs the
binaries, creates the unprivileged worker user, installs the units and drop-ins, and reloads
systemd — from a built tree to enabled services with no hand-editing. Upgrade is documented and
leans on the fail-open watchdog (D18): replacing the agent binary and restarting cannot hang a
machine, because the watchdog answers the kernel regardless, so a restart is safe under load.

**Validated, not just written.** The units are checked with `systemd-analyze verify` so a
malformed directive fails here, not on a deployer's box. Full install-and-run needs a systemd host
(a documented smoke test, like the compose stack), but the unit correctness is machine-checked.

## What this does NOT claim or cover

- **It does not run a full install in CI.** Installing units and starting services needs a systemd
  host and root; CI validates unit SYNTAX (`systemd-analyze verify`) and the code. A real
  install-start-upgrade cycle is a documented manual smoke test.
- **It is not a distro package (.deb/.rpm) or a signed artifact.** Those are a release-engineering
  step; this is the systemd + install-script layer they would wrap. Stated so the scope is clear.
- **It does not harden beyond what the decisions already specify.** The units express D13/D29/D35/
  D18; they do not invent new hardening. seccomp is the worker's in-process filter (T-012); the
  cgroup limits are the existing drop-in.
- **It does not manage secrets or TLS.** Production credential and TLS management is out of scope
  (as it was for the dev compose stack); the units read the same env vars the binaries already use.
- **The agent/worker units assume Linux + systemd.** Only Linux ships (D9); a non-systemd init is
  not packaged.

## Decisions

Depends on **D13/D29** (privilege split; the privileged process holds only what it needs),
**D35/T-012** (the sandboxed worker and its hardening drop-in), **D18** (the watchdog makes a
restart safe), **D41/T-023** (the control plane), and the environment constraint (Podman/systemd,
rootless where possible).

No new architectural decision — this PACKAGES the existing ones. It records the operational fact
that the privilege split is enforced by the unit files (agent: CAP_SYS_ADMIN only; worker:
unprivileged user + hardening), install is `deploy/install.sh`, and upgrade is safe because of the
fail-open watchdog.
