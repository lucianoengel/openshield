## Why

PLAT-9's acceptance says an upgrade must "roll forward and back". Rolling the binary back is a legitimate
and common incident action, and today it is **silently unsafe**: `fullyMigrated` returns
`applied >= want`, so a binary that knows 30 migrations, meeting a database that has had 36 applied,
concludes it is fully migrated and starts. It then reads a schema it does not know — where a column may
have gained meaning, a constraint may reject its writes, and a table it never heard of holds state it will
not maintain.

Nothing reports this. An operator rolling back during an incident gets no signal that the node is now
running behind its own database.

## What Changes

- **Schema skew is detected and reported.** The binary compares the migrations it embeds with those the
  database has applied and reports three states: *behind* (it will migrate), *level*, and **ahead of the
  binary** — the rollback case.
- **A binary running against a newer schema starts, LOUDLY.** It does not refuse: refusing would make
  rollback impossible after any migration, which is worse than the risk it avoids and would break the very
  property PLAT-9 asks for. It warns, names the gap, and exposes it as a metric so a fleet running mixed
  versions is visible rather than inferred.
- **The asymmetry is documented where it bites**: migrations are forward-only, so rolling the **binary**
  back is supported and rolling the **schema** back is not. An operator needs to know that before they
  need it.

## Capabilities

### Modified Capabilities
- `packaging`: adds schema-skew detection and reporting across binary upgrade and rollback.

## Impact

- **New code**: `SchemaSkew` in `internal/store/postgres`; the server reports it at boot and exposes it on
  `/metrics`.
- **No migration, no proto change, no new dependency.**
- **Honest scope**: this makes rollback *observable*, not *safe in general*. A binary cannot know what a
  newer migration changed, so the guarantee is bounded: skew is reported, and how much skew is acceptable
  remains an operator judgement informed by the release notes. It does not implement schema downgrade
  (forward-only is deliberate), does not orchestrate a rolling upgrade (systemd/Helm own that), and does
  not gate agent↔server wire compatibility, which protobuf handles field-wise and the signed envelopes
  handle with explicit version rejection.
