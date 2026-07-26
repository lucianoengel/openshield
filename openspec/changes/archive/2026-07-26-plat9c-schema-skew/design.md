## Context

`fullyMigrated` returns `applied >= want`. The `>=` is what makes rollback silent: a binary embedding 30
migrations against a database with 36 applied concludes it is fully migrated and starts with no signal.

## Goals / Non-Goals

**Goals:** detect and report schema skew in all three directions; keep startup working under skew; expose
it as a metric; document the forward-only asymmetry.

**Non-Goals:** schema downgrade; rolling-upgrade orchestration; wire-compatibility gating.

## Decisions

### Report, do not refuse

The tempting fix is to refuse to start against a newer schema. It is wrong: rolling a binary back is a
legitimate incident action, and a binary that refuses turns a rollback into an outage — breaking the very
property PLAT-9 asks for. The risk it would avoid (reading a schema whose changes are unknown) is real but
bounded and usually benign, because migrations here are additive by convention.

So: start, warn loudly, and make the state queryable. The failure this prevents is not "a binary ran
against a newer schema" — it is "a binary ran against a newer schema **and nobody knew**".

### The asymmetry is the thing to document

Migrations are forward-only. That means rolling the **binary** back is supported and rolling the **schema**
back is not, and the two are easy to conflate under pressure. Stated in the spec and at the point the skew
is reported, because an operator needs it before they need it.

### Skew is a metric, not only a log line

A fleet mid-rollback has some nodes behind their schema and some level. A log line answers that per host;
a gauge answers it for the fleet, which is the question actually being asked during an upgrade.

## Risks / Trade-offs

- **A binary reading an unknown schema can still misbehave** → bounded, not eliminated; reported so the
  window is visible and short.
- **`applied > want` can also mean a stray row** → reported the same way, and a stray row in
  `schema_migrations` is itself worth knowing about.

## Migration Plan

No schema change. A level deployment reports no skew and behaves exactly as before.

## Open Questions

- Whether a *tolerated* skew bound (refuse beyond N) is worth adding once there is real data on how often
  rollbacks cross migrations — deliberately not guessed now.
