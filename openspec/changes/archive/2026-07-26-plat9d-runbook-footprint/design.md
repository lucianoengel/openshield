## Context

The operational surface built this cycle — signed releases with verification, an emergency disable,
verified restore, schema-skew reporting, database-backed configuration — is undocumented as a whole.

## Goals / Non-Goals

**Goals:** state the deployment footprint; document the procedures that exist; bind the component list to
reality with a test.

**Non-Goals:** backup tooling, upgrade orchestration, HA guidance beyond the existing leader lease,
measured sizing figures.

## Decisions

### The component list is a test, not prose

Documentation drifts silently, and a runbook is consulted under pressure. Binding the documented set to
`cmd/` in both directions makes the one part that must be correct — *what exists* — impossible to get
wrong without failing the build. It is the same discipline as the config schema being derived from what
the code reads (D262) and every OPENSHIELD_* variable being checked against the declarations.

### Footprint is stated as SHAPE, not as measured numbers

"Single control plane, Postgres, NATS, N agents" is a true statement about the architecture. "Handles
10,000 endpoints on 4 vCPU" would be a number this project has not measured, and publishing an unmeasured
figure is exactly the overclaim its review rounds exist to catch. The footprint section therefore says
what the deployment *is* and what it is *not* — and says plainly that no sizing exercise has been run.

### Limits are documented next to the procedure, not in a caveats section

Each procedure carries its own bound where it is used: restore verification says anchor cadence limits
what completeness proves; the emergency disable says the fleet path does not reach endpoint agents; schema
skew says migrations are forward-only. A caveats section at the end is a section nobody reads.

## Risks / Trade-offs

- **A runbook can still rot in its prose** → the test binds the component list, which is the part most
  likely to change and most costly to get wrong; the rest is bounded by the docs-claims denylist already
  in CI.

## Migration Plan

Documentation only.

## Open Questions

- Whether sizing guidance should wait for a real load exercise or be omitted permanently — omitted for
  now, and marked as unmeasured rather than absent.
