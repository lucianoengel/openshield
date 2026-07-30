# Tasks

- [x] `Stack.RestoreBroker` — a new broker on the ORIGINAL host port, with retry for the port-release race.
- [x] Move the broker's JetStream store into a named volume so a restart is a restart.
- [x] `Stack.RestoreBrokerEmpty` — the fresh-store case, kept reproducible in one call.
- [x] `TestASpooledOutageDrainsWhenTheBrokerReturns` — assert the spool DRAINS and the records are STORED.
- [x] Fix the delivered-versus-stored race in the assertion (an `Eventually`, not a single read).
- [x] Mutation-verify: `Flush` as a no-op must fail the scenario.
- [x] Confirm the harness change does not disturb the existing outage/restart/enrollment scenarios.
- [x] Record the empty-broker defect as PLAT-10, with the reproduction and why a half-fix is worse.
- [x] `docs/unwired-audit.md` — Round 47.
- [x] `make quick` green.
