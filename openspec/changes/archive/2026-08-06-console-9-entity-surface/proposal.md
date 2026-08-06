# CONSOLE-9 · Entity surface over HTTP

## Why

The device⋈user entity graph (D203) and per-entity risk (D255) have both been live for a long time and
**both are database-only**. No HTTP route exposes either.

Worse than a missing route: **`xdr.Store` has no reader at all.** `Resolve`, `LookupAny` and `Link` each
answer *"what is the id for THIS name"*; not one of them can answer *"what does the platform know"*. So
the coalescing this whole lane exists to perform — every domain's detections resolving to one asset — has
been invisible to the operators it was performed for.

The console's central interaction is the pivot: from one alert, "this device is also known as what, and
to whom?" Nothing could answer it.

## What Changes

- **`xdr.Store.Entities`** — enumerate the graph, newest first, each entity with its aliases.
- **`xdr.Store.EntityFor`** — resolve one alias value to its entity and every other name it carries.
  It does **not** create on miss, unlike `Resolve`.
- **`GET /entities`** — the graph joined to risk, or one entity via `?value=`.
- Risk is **absent** where no alert in the window concerns the entity, never zero.

## Impact

- Affected specs: `entity-model`, `control-plane`.
- No proto change, no migration. Read-only.

## The privacy boundary, stated because this sits beside the CONSOLE-1 split

The graph is **pseudonym⋈pseudonym**: a device's canonical pseudonym linked to the pseudonym of a user
identity (IDENT-1/D23), never a name. Resolving a pseudonym to a person is `/subject` — the privacy
officer's route, which no operator tier reaches (D470).

This surface answers "these detections concern one asset", which is the analyst's pivot from an alert.
Hiding it from the tier that triages alerts would leave them reading one asset's activity as several
unrelated ones, which is the specific error the entity model exists to prevent.
