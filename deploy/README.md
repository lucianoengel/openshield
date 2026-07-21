# Deploying OpenShield

## Dev stack (backend only)

```
podman-compose up -d
```

Brings up Postgres + NATS + the control plane. See the repo root `compose.yaml`.
This is a **dev stack** (default credentials, no TLS), not production.

## Installing the agent + control plane (systemd)

From a built tree, as root:

```
sudo deploy/install.sh
```

Idempotent — installs the binaries to `/usr/local/bin`, creates the `openshield`
and `openshield-worker` system users, installs the systemd units and hardening
drop-ins, reloads systemd, and enables the services. Re-running it updates in
place.

The **agent is enabled but not started** — fanotify marks on an unconfigured host
are the operator's call:

```
sudo systemctl start openshield-agent
```

### What the units enforce

The privilege split (D13/D29) is encoded in the units, not left to the deployer:

- **`openshield-agent.service`** — the privileged half. Root, but bounded to
  **only `CAP_SYS_ADMIN`** (fanotify), not the full root capability set. Never
  parses attacker bytes.
- **`openshield-worker.service`** — the unprivileged half. A dedicated non-login
  user, **no capabilities**, seccomp network-deny (in-process, T-012) plus the
  cgroup/namespace hardening drop-in (D35). All parsing is contained here.
- **`openshield-server.service`** — the control plane. An ordinary service, no
  special privilege.

## Upgrade

```
git pull && sudo deploy/install.sh && sudo systemctl restart openshield-agent
```

Restarting the agent is **safe under load**: the fail-open watchdog (D18) answers
the kernel regardless of pipeline state, so a permission event during the restart
window fails open (audited) rather than hanging a blocked process. That is why the
watchdog was built even though Phase 1 does not enforce.

## Not covered here

- Distro packages (`.deb`/`.rpm`) or signed artifacts — a release-engineering step
  this systemd layer would be wrapped by.
- TLS and secrets management — production concerns; the units read the same env
  vars the binaries do.
- Non-systemd init systems. Only Linux + systemd is packaged (D9).

Full install-start-upgrade validation needs a systemd host with root; the unit
files themselves are checked with `systemd-analyze verify` in review.


## Real container end-to-end test

```
bash deploy/e2e.sh
```

Brings up the compose stack (Postgres + NATS + the **openshield-server binary in a
container**), publishes telemetry over the real NATS, verifies all three kinds
(event / classification / decision) land in the real Postgres, then tears down and
restores the dev Postgres — on any exit. This closes the gap the in-process tests
leave: it exercises the built binary, its container config, its DSN and the real
NATS wire, not just the Server struct. Not a CI job by default (it builds an
image); run it on demand.
