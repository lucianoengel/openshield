## 1. Harness
- [x] 1.1 Ephemeral-port Postgres and NATS (JetStream) with per-run names and full teardown.
- [x] 1.2 Build the commands once; run them as supervised subprocesses with captured output.
- [x] 1.3 Readiness by log line or observable effect; `pg_isready` rather than a TCP dial.
- [x] 1.4 Skip without podman.

## 2. First scenarios
- [x] 2.1 The binary migrates a fresh database and the product's tables exist.
- [x] 2.2 A malformed BOOTSTRAP setting stops the boot, naming field and constraint.
- [x] 2.3 A DYNAMIC setting in the environment is ignored, not applied.
- [x] 2.4 `config` reports origins and never prints a secret.

## 3. Land
- [x] 3.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green, suite included.
- [x] 3.2 Record D282, including the e2e-script defect this surfaced.
- [x] 3.3 Sync specs and archive.
