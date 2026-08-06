# Per-test databases in the integration harness

## Why

**Retroactive change for D478 (`0dc8774`), written to repair a workflow gap: the fix shipped without one.**

`DSNFor(t, name)` creates an extra database in the suite's SHARED Postgres so two components do not share
a forward-secure ledger chain. Its convention was *pick a name nobody else used* — knowledge every new
test has to carry, enforced by nothing.

Two tests asked for `"endpoint"`. Both passed under `-run` every time; the full suite failed with
`database "endpoint" already exists`, and two CI runs went red.

`e2e-verification` **already requires** that the suite not depend on fixed names — but the existing
requirement is about infrastructure the suite STARTS (ports, container names). It does not reach resources
created *inside* a running stack, which is where this bit.

## What Changes

- The database name is scoped to the calling test, so `endpoint` in two tests is two databases.
- Truncation to Postgres's 63-byte limit keeps the TAIL of the test name.
- The requirement is extended to cover resources created inside a stack, not only the stack itself.

## Impact

- Affected specs: `e2e-verification`.
- Test-harness only. No product code, no migration.
