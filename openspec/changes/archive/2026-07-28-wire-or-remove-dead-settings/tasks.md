## 1. Make the prune read its setting

- [x] 1.1 The cutoff comes from OPENSHIELD_NOTIFY_DEDUPE_RETENTION instead of a hardcoded 24h.
- [x] 1.2 The recorded compliance policy string is built from the value ACTUALLY used, so the audit
      trail stops citing a knob nobody read.

## 2. Remove the dead setting

- [x] 2.1 Drop `OPENSHIELD_POSTURE_PUBKEY` from the gateway's declarations.
- [x] 2.2 Correct the provisioning tool's message, which still tells operators to install it.

## 3. Close the class

- [x] 3.1 A guard asserting every declared setting is read somewhere in the module, comments stripped.
- [x] 3.2 Fixtures: a comment-only mention does NOT count; a library-only read DOES.
- [x] 3.3 Mutation: re-declare a dead setting -> the guard fails naming it.

## 4. Prove and land

- [x] 4.1 Integration: the dedupe ledger is pruned to the retention, and a recent id survives.
- [x] 4.2 `make quick`, package tests.
- [x] 4.3 Record in `docs/unwired-audit.md`; commit with a D-number, archive WITH sync, check CI.
