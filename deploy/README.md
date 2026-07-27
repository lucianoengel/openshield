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
make integration
```

Brings up the compose stack (Postgres + NATS + the **openshield-server binary in a
container**), publishes telemetry over the real NATS, verifies all three kinds
(event / classification / decision) land in the real Postgres, then tears down and
restores the dev Postgres — on any exit. This closes the gap the in-process tests
leave: it exercises the built binary, its container config, its DSN and the real
NATS wire, not just the Server struct. Not a CI job by default (it builds an
image); run it on demand.


## Multi-agent fleet simulation

```
make integration
```

Brings up the control plane + Postgres + NATS and N **agent containers**, each
enrolling over HTTP with its own identity and publishing **verified** signed
telemetry + heartbeats. It asserts the fleet properties: verified+attributed
telemetry, liveness, the **dead-man's-switch** on a killed agent, and
**revocation** rejecting a revoked agent's telemetry — then tears down and
restores the dev Postgres. Fanotify permission mode is NOT simulable in rootless
podman (it needs init-namespace CAP_SYS_ADMIN), so this proves the fleet CONTROL
path, not kernel eventing.

## Network connectors — the DNS listener MUST be a mirror, never inline (DEPLOY-1)

The engine's DNS connector (`OPENSHIELD_DNS_LISTEN`) is **observe-only**: it parses queries and
feeds them into the pipeline, but it **never answers a query** — it is a monitoring endpoint, not a
resolver. Deploy it on a **tap / mirror** of DNS traffic, so the fleet's real resolver still answers:

- **A SPAN/mirror port** (switch port mirroring), or
- **An eBPF / `AF_PACKET` tap** that copies query datagrams to the listener,

sending a **copy** of each query to `OPENSHIELD_DNS_LISTEN` while the production resolver is
untouched.

**Do NOT** steer real `:53` traffic to the listener with a transparent redirect (nftables/iptables
`REDIRECT`/`DNAT` to the listener port). Because the listener does not reply, an inline redirect
would **blackhole the fleet's DNS** — every lookup would hang and time out. The listener's admission
rate limit (NIPS-7) bounds ledger writes under a flood, but that is a safety bound, not a licence to
put it inline. Answering queries (a real resolver/forwarder mode) is a separate, deliberate build;
until then, mirror-only.

The same applies to the syslog and SMTP connectors: they are capture endpoints fed a copy of the
traffic (or a dedicated capture destination), not inline elements the fleet depends on for delivery.

## The end-to-end scripts are gone (D296)

`e2e.sh`, `fleet-e2e.sh`, `mtls-e2e.sh` and `observe-e2e.sh` were deleted, and their distinctive
coverage lives in `test/integration/` — run by `make integration`, which is part of `make all`.

They were not removed for being redundant. Each proved something nothing else did: the shipped engine
detecting a real file, the anchor binary moving completeness to `anchored`, revocation making a trusted
agent untrusted, the dead-man's-switch, and an agent without a client certificate being refused. They
were removed because they sat outside every gate, and one of them had already stopped passing without
anyone noticing — porting the observe script found that **the engine never stamped a purpose on the
events its own connectors produce**, so every fanotify event failed validation and the observe path was
broken at the binary level while every package test passed.

`install.sh` stays. It is a product artifact, not a test, and `internal/packaging` parses it to assert
the privilege boundaries it sets up.
