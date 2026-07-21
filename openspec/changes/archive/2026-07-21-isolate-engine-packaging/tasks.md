# Tasks — package & isolate the engine

## 1. The engine unit

- [x] 1.1 `deploy/systemd/openshield-engine.service`: `User=/Group=openshield-engine`, empty `CapabilityBoundingSet`, `NoNewPrivileges=true`, `ProtectSystem=strict`, `PrivateTmp`, `ProtectHome`, `StateDirectory=openshield-engine`, `OPENSHIELD_SIGNER_FILE` under that dir, DSN/WORKER_BIN defaults, `OPENSHIELD_WATCH_DIRS` commented with guidance.

## 2. Installer

- [x] 2.1 `install.sh`: `ensure_user openshield-engine`; install `openshield-engine.service`, `openshield-anchor.service`, `openshield-anchor.timer`; enable the engine; keep the agent enabled-not-started.

## 3. Build-time isolation guard

- [x] 3.1 **Test (Go)**: parse the engine unit + install.sh and assert `User=openshield-engine` (not root, not `openshield`/agent), `NoNewPrivileges=true`, no `CAP_SYS_ADMIN`/all-caps grant, a `StateDirectory`; and that install.sh creates the engine user and installs the engine + anchor units.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D68: the engine (signer key + OPA holder) is isolated under its own dedicated user + unit; the anchor timer is installed; closes the D45/D48 packaging gap; host root still wins (D16).
- [x] 4.2 `openspec validate isolate-engine-packaging --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| engine runs as the monitored `openshield` user | `TestEngineUnitIsolatesTheSignerHolder` |
| engine grants CAP_SYS_ADMIN | `TestEngineUnitIsolatesTheSignerHolder` |
| installer omits an engine/anchor unit | `TestInstallerInstallsEngineAndAnchor` |

The engine — holder of the ledger signer key + OPA — is now installed and isolated
under a dedicated `openshield-engine` user and systemd unit (not root, not the
monitored account), with the signer state confined to its own StateDirectory; the
anchor service + timer are installed so anchoring runs. A build-time Go test fails
if the isolation regresses. Host root still wins (D16) — this closes the wrong-user
erosion (D45/D48), not a root compromise.
