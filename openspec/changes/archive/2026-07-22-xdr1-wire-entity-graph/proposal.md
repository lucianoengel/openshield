## Why

The XDR entity graph (`internal/xdr`, migration 021) shipped as REAL, race-tested code (XDR-1, D195)
but is **orphaned — zero runtime callers**. Nothing populates `entities`/`entity_aliases`, so the
device⋈user join exists only as a store, and `TestCanonicalJoin` proves only that two in-test
`pseudonym.Of` calls hash the same — a tautology, not that two *real producers* converge on one entity.
The entire XDR correlation lane (XDR-2 → XDR-7) is dead in the water until real producers feed the
graph. This is the R34 priority-lane item **XDR-1-WIRE**, to be done **before XDR-2**.

## What Changes

Wire the shipped store into the real runtime so both identity domains populate it:

- **Control plane — enrollment**: when an agent enrolls, resolve its canonical device entity
  (`Resolve(KindDevice, pseudonym.Of(agentID))`).
- **Control plane — telemetry ingest**: when a verified `event` is persisted, resolve the device
  entity for the event's canonical subject (`Resolve(KindDevice, subject)`), so every domain's
  telemetry populates the graph.
- **Gateway — dual-credential identity**: when the access proxy authenticates a request with BOTH a
  device certificate and a verified OIDC user, link them (`Link(KindDevice, deviceSubject, KindUser,
  userSubject)`) — the device⋈user join, from the real ZT-3 path.

All graph writes are **best-effort and off the failure path**: a graph error is counted and logged,
never breaks ingest, enrollment, or an auth decision (the graph is a derived index, not the system of
record — D38). The gateway link runs asynchronously so it never adds latency to a proxied request.

The device cert CN, the engine's `Event.Subject`, and enrollment all derive the device id through the
one canonical `pseudonym.Of` (IDENT-1), so a device resolves to the SAME entity id across all three
producers — which is exactly what the strengthened XDR-1 acceptance (and test #1) demands.

## Capabilities

### New Capabilities
- `entity-graph-population`: the runtime producers (enrollment, verified telemetry ingest, and the
  gateway's dual-credential path) that populate and link the cross-domain entity graph, so a device
  resolves to one entity across domains via real ingest — not an in-test derivation.

### Modified Capabilities
<!-- none: no existing capability's REQUIREMENTS change; this wires an existing store into runtime paths. -->

## Impact

- `internal/controlplane`: `Server` gains an `*xdr.Store` (built from its pool); `Enroll` and the
  signed-ingest path resolve the device entity best-effort; a `EntityResolveFailures` counter.
- `internal/gateway`: `AccessProxy` gains an optional `*xdr.Store` + `SetEntityGraph`; `ServeHTTP`
  links device⋈user asynchronously when OIDC yields a distinct user.
- `cmd/openshield-server`, `cmd/openshield-gateway`: construct the store from the existing pool and
  wire it in.
- No proto change, no core change, no new dependency. The `internal/xdr` store API is unchanged.
- Test #1 (entity-join E2E): a real engine `SetSubject` → signed transport → `handleSigned` device
  resolve, asserted equal to the id enrollment (a second real producer) resolves — killing the
  `TestCanonicalJoin` tautology.
