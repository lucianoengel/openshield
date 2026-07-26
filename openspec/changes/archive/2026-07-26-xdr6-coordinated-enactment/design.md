## Context

Shipped at D254 (`455b4c5`), on top of D252 (the signed, four-eyes-gated intent) and D253 (endpoint
enactment).

## Goals / Non-Goals

**Goal:** make the spec describe the shipped coordination property.
**Non-Goals:** any code change; alert-storm suppression; enactments beyond flows and execs.

## Decisions

### D-1: The intent id rides `Context.Version`

Migration 001 warns that adding a column to `audit_entries` changes what is hashed and breaks chain
continuity. `Context.Version` already exists so a replay can evaluate against the Context that actually
applied (D27), and `core/audit.go` already copies it onto the ledger entry — so stamping the intent id
there makes both enactments correlatable with nothing new hashed.

This is the general lesson worth keeping: **when something must reach the ledger, look for an existing
hashed field before adding one.**

### D-2: The gateway consults intents only when a store is installed

Without one it behaves exactly as before. Consumption is opt-in in both domains, which is what makes
partial containment possible — and why the proposal states it.

## Risks / Trade-offs

- **Spec-after-code**, as with its endpoint counterpart: the delta was written against shipped code and its
  tests rather than the reverse, and is labelled retroactive so nobody reads it as a prior design.
- **Partial containment is a real operational hazard** — one domain enacting while another silently does
  not. Named here; detecting it would need per-domain enactment telemetry, which is not built.

## Migration Plan

None — documentation of shipped behaviour.
