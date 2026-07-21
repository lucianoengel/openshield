## 1. systemd units

- [x] 1.1 `deploy/systemd/openshield-agent.service`: root, AmbientCapabilities + CapabilityBoundingSet
      = CAP_SYS_ADMIN only (fanotify); never parses attacker bytes (D29)
- [x] 1.2 `deploy/systemd/openshield-worker.service`: User=openshield-worker, empty
      CapabilityBoundingSet; the existing hardening drop-in applies (D35)
- [x] 1.3 `deploy/systemd/openshield-server.service`: User=openshield, After network-online, reads
      OPENSHIELD_DSN/OPENSHIELD_NATS_URL, restart on-failure

## 2. Install script

- [x] 2.1 `deploy/install.sh`: idempotent — install binaries, create openshield + openshield-worker
      system users if absent, install units + drop-ins, daemon-reload, enable; refuse without root;
      do NOT auto-start the agent

## 3. Upgrade + validation + docs

- [x] 3.1 Document the watchdog-safe upgrade path (build → install.sh → restart) in deploy/README.md
- [x] 3.2 Validate every unit with `systemd-analyze verify`; record the result
- [x] 3.3 Note in `docs/decisions.md` (new D-number): units enforce the split (agent CAP_SYS_ADMIN
      only; worker unprivileged + hardening); install is one idempotent script; upgrade is
      watchdog-safe; not a distro package, full install is a manual smoke test
- [x] 3.4 Mark T-027 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

`systemd-analyze verify` parses all three units with NO directive errors — the
only complaint is that the binaries are not yet at /usr/local/bin (install.sh
places them there; it needs root). `install.sh` passes `bash -n` and is idempotent
by construction (user/create guards, install -m, daemon-reload). All four cmd
binaries build. The units encode least privilege: agent bounded to CAP_SYS_ADMIN,
worker with an empty capability set + the hardening drop-in, server unprivileged.
The upgrade path is documented as watchdog-safe (D18) in `deploy/README.md`.

Honest boundary: a full install-start-upgrade cycle needs a systemd host + root
and is a documented manual smoke test — the same boundary as the compose stack's
`podman-compose up`. Not a distro package; that is release engineering. Docs: D45.
