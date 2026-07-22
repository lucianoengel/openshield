## Context

`internal/xdr.Store` (D195, migration 021) implements `Resolve(kind, value) → entityID` (atomic
find-or-create under a per-alias advisory lock) and `Link(kindA, valA, kindB, valB)` (device⋈user
merge, deadlock-safe). It is correct and race-tested but has **zero runtime callers**. IDENT-1 already
unified the device identity derivation: the engine's `SetSubject` stamps
`Event.Subject.PseudonymousId = pseudonym.Of(agentID)`, the gateway's `FromClientCert` yields
`canonid.Of(CN) == pseudonym.Of(agentID)`, and enrollment keys on the same `agentID`. So a device is
already named by ONE value everywhere — the only missing piece is calling the store.

## Goals / Non-Goals

**Goals:**
- Populate the device side of the graph from TWO independent real server-side producers (enrollment +
  verified telemetry ingest), so it stops being orphaned and two real producers demonstrably converge.
- Create the device⋈user link from the real gateway dual-credential path.
- Keep every graph write best-effort and off the failure/latency-critical path.
- Prove convergence through the REAL ingest path (test #1), killing the `TestCanonicalJoin` tautology.

**Non-Goals:**
- Cross-domain correlation over the graph (that is XDR-4). This ticket only *populates* it.
- Session/IP alias kinds beyond device+user (future XDR work).
- Reading the graph from any query path yet (XDR-5 timeline).
- Changing the `xdr.Store` API, the proto, or the frozen core.

## Decisions

1. **Graph is always-on, built from the existing pool.** `controlplane.New` and the gateway construct
   `xdr.NewStore(pool)` directly rather than gating behind an env var — the entity graph is core
   infrastructure keyed off tables that exist after migration, and every write is best-effort so a
   missing table only increments a failure counter. The gateway's `SetEntityGraph` is provided for
   symmetry/tests.

2. **Best-effort, never fail the primary action.** A `Resolve`/`Link` error is logged and counted
   (`EntityResolveFailures`), never propagated — the graph is a derived index (D38), not the ledger.
   Enrollment succeeding but the graph write failing must still enroll the agent; an ingest that
   persisted must still be `ingestPersisted`.

3. **Where each producer writes:**
   - *Enrollment* (`Server.Enroll`): after the tx commits, `Resolve(KindDevice, pseudonym.Of(agentID))`.
     After-commit so a graph error cannot roll back a real enrollment.
   - *Ingest* (`handleSigned`): after a verified `event` is persisted, `Resolve(KindDevice, subject)`
     where `subject = ev.Subject.PseudonymousId`. Reuses the already-decoded subject; only for
     `kind=="event"` (classifications/decisions carry no subject).
   - *Gateway* (`AccessProxy.ServeHTTP`): when OIDC is on and produced a user distinct from the device,
     `go Link(KindDevice, deviceID.Subject, KindUser, userID.Subject)` — asynchronous, so a proxied
     request never waits on a graph write.

4. **Synchronous on the server, async on the gateway.** The server-side resolves are inline
   (best-effort) because they are cheap and the ingest path already does inline DB work; this also
   makes test #1 deterministic (the device entity exists by the time ingest returns). The gateway link
   is fire-and-forget to protect per-request latency; its test uses a `waitFor`.

5. **Test #1 shape.** A real `engine.SetSubject(agentID)` + a `PROCESS`/`FILE` event → real signed
   transport → `handleSigned` → assert `graph.Resolve(KindDevice, pseudonym.Of(agentID))` equals the id
   `Enroll` (the second real producer) recorded. The mutation: removing the ingest resolve makes the
   two ids diverge (ingest creates nothing; the assertion that both real producers share one id fails).

## Risks / Trade-offs

- **Added write on the ingest/enroll path.** One short indexed upsert per verified event/enroll. It is
  best-effort and the `entity_aliases(kind,value)` unique index makes the common (already-resolved)
  case a single indexed SELECT. Acceptable; the alternative (a batch/async resolver) adds complexity
  the correlation lane does not yet need.
- **Async gateway link can lag.** The device⋈user edge may appear a few ms after the request. That is
  fine — nothing reads the graph synchronously yet, and correlation (XDR-4) is windowed.
- **A flood of first-sight devices** each take the per-alias advisory lock briefly. The lock is keyed
  per-alias (`hashtext`), so distinct devices do not serialize; a hash collision only over-serializes
  two unrelated aliases briefly (already the store's documented, harmless behavior).
