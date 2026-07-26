## Context

Enforcement is invoked from exactly two places — `internal/engine` (endpoint) and `internal/gateway`
(network) — each guarding with `core.CanEnforce`. PLAT-5b gave the server a dynamic setting store with a
watcher that propagates a change fleet-wide within one poll interval; that is the distribution mechanism
this needs, already built.

## Goals / Non-Goals

**Goals:** one kill switch used by both call sites; enforcement downgraded to observation; detection and
audit untouched; every suppression recorded; two activation paths; fail toward enforcing.

**Non-Goals (the rest of PLAT-9):** rolling upgrade, version skew, rollback, backup + verified restore,
DR runbook, deployment footprint. Also out: revoking already-published intents, and stopping ingestion.

## Decisions

### The switch lives in `core`, used by both call sites

Not implemented once per call site. A kill switch that is honoured by the gateway and forgotten by the
endpoint is worse than none — the operator believes enforcement stopped, and it did not. One
implementation, consulted at both guards, is the only version of this that can be relied on under
pressure.

### Downgrade to observation, do not stop the pipeline

The switch sits between the Decision and the Enforcer. Everything before it runs unchanged: the event is
classified, the policy decides, the ledger records. Only the enforcement call is skipped.

That ordering is the whole design. A kill switch implemented earlier — refusing to classify, or dropping
events — would also destroy the record of what happened while enforcement was off, which is precisely the
period an operator will need to reconstruct. Stop acting; keep seeing.

### Fail toward ENFORCING, which is the opposite of most fail-safes here

The watchdog fails open (D17) because a dead DLP that blocks everything gets uninstalled. This one fails
the other way: if the switch's state cannot be read, enforcement CONTINUES.

The asymmetry is deliberate. A read error that silently disabled enforcement would mean a corrupted file,
a permissions change, or an unreachable database quietly turns the product off across a fleet — an
availability failure converted into a security failure. The switch must be *affirmatively* engaged, and
absence is never engagement.

### Two paths, because there are two different failures

A **local break-glass file** works when the control plane is unreachable, which is exactly when an
operator most needs to stop enforcement. It requires root on the host — which D16 already treats as
game-over for that host, so it grants nothing an attacker did not already have.

A **dynamic setting** propagates fleet-wide within one poll interval via PLAT-5b's watcher, and is the
path that answers "stop the fleet". It only reaches components that read the config store: endpoint agents
do not, so their fleet-wide disable needs the signed channel and is increment 2. Stated plainly rather
than implied, because "fleet-wide" that quietly excludes the endpoints would be the overclaim this
project's review rounds exist to catch.

### Suppressions are counted individually

Not just "the switch is on". An operator asking "what did we not block during those forty minutes" needs a
number and a reason, and a counter that only reports switch state cannot answer it.

## Risks / Trade-offs

- **An attacker with root engages the local switch** → they already own that host (D16); the fleet path is
  unaffected and the engagement is recorded.
- **The local file is per-host** → deliberate; the fleet path exists for the fleet, and the gap for
  endpoint agents is named.
- **Suppression volume during a long disable** → counted, not per-event alerted; the ledger already holds
  each decision.

## Migration Plan

No schema change. With no break-glass file and no setting, behaviour is exactly as before.

## Open Questions

- Whether the endpoint's fleet-wide disable should ride the response-intent channel (a fourth verb) or its
  own signed message — deferred to increment 2, since a verb meaning "stop enforcing" sits oddly in a
  vocabulary whose other members *cause* enforcement.
