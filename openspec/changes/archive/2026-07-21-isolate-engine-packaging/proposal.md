## Why

Audit finding #5, verified: `openshield-engine` holds the forward-secure ledger
SIGNER key (D46), the OPA policy, and the pgx connection (D48) — but `install.sh`
installs no systemd unit and no dedicated user for it, and the anchor units (D64)
are not installed either. D45 claimed the privilege split is enforced by the
systemd units, not left to the deployer — but D48 (the engine) shipped AFTER D45
and never closed that loop. So a deployer running the pipeline runs the engine
under whatever account is convenient, plausibly the very user being MONITORED,
putting the signer key and OPA under no isolation — the erosion-to-everything-as-
the-monitored-user D45 warns about.

## What Changes

- `deploy/systemd/openshield-engine.service` runs `openshield-engine` under a
  DEDICATED non-login system user (`openshield-engine`) — not root, not the
  monitored account. Unprivileged (notify-mode fanotify needs no capabilities,
  D52): `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, an empty
  `CapabilityBoundingSet`, and a `StateDirectory` for the signer state so only
  that directory is writable and the key is owned by the engine user. The observe
  env (`OPENSHIELD_WATCH_DIRS/DSN/WORKER_BIN/SIGNER_FILE`) is present as commented
  defaults the operator sets.
- `install.sh` creates the `openshield-engine` system user (idempotent), installs
  the engine unit, ALSO installs the already-built anchor `service`+`timer` (D64),
  and enables the engine; the agent stays enabled-not-started.
- A Go test reads the unit files and `install.sh` and asserts the isolation, so a
  regression that drops it fails the build.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `packaging`: the engine — holder of the signer key + OPA — is installed and
  isolated under its own dedicated user and systemd unit, closing the D45/D48 gap;
  the anchor timer is installed so anchoring actually runs.

## Impact

- New: `openshield-engine.service`; `install.sh` engine user + engine/anchor unit
  install + enable; a packaging Go test; docs (D68).
- HONEST bound (D16): host root still wins. This stops the WRONG-USER erosion (the
  signer key + OPA no longer run under the monitored account), not a root
  compromise. Respects D45 (units enforce the split) and D48 (three roles).
