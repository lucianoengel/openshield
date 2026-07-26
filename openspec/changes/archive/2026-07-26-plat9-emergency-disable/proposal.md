## Why

"How do I stop this?" is the question a CISO asks before "what does it detect?", and today OpenShield has
no answer. Every enforcement path — the gateway blocking flows, the endpoint denying execs, the print
filter aborting jobs, the USB enforcer — can only be stopped by stopping the software, which also stops
the detection and the audit trail. That is the worst possible trade to have to make during an incident
that the product itself is causing.

## What Changes

- **A kill switch in `core`**, used by BOTH enforcement call sites (engine and gateway) rather than
  implemented twice. When engaged, an enforcing Decision is **downgraded to observe** before any enforcer
  runs.
- **"Stop enforcing" is not "stop seeing".** Classification, decision-making and the audit ledger continue
  unchanged while the switch is engaged. The trail of what *would* have been enforced is exactly what an
  operator needs afterwards, and losing it is how a kill switch becomes a blindfold.
- **Every suppression is recorded**, individually and loudly. A silent kill switch is indistinguishable
  from a product that has stopped working.
- **Two activation paths, for two different failures.** A **local break-glass file** works when the
  control plane is unreachable — which is precisely when you need it most. A **dynamic configuration
  setting** propagates fleet-wide within one poll interval, using the watcher PLAT-5b already built.
- **The switch must be affirmatively engaged.** If its state cannot be determined — an unreadable file, a
  failed config read — enforcement CONTINUES and the error is logged. A read error must never silently
  disable the product.

## Capabilities

### Modified Capabilities
- `enforcement`: adds a fail-safe, audited emergency disable that downgrades enforcement to observation
  without stopping detection.

## Impact

- **New code**: `internal/core/killswitch.go`; both enforcement call sites consult it.
- **No migration** — the fleet-wide path is a dynamic setting, which PLAT-5b already stores and
  propagates. **No proto change, no new dependency.**
- **Honest scope**: this is **increment 1 of PLAT-9**. Rolling upgrade with version-skew tolerance and
  rollback, backup + verified restore (re-verifying the hash chain and anchors, not just the bytes),
  node/DB recovery and the DR runbook, and the documented deployment footprint are **not** in this change.
  The fleet-wide path covers server-side components that read the config store; **endpoint agents do not
  read it**, so their fleet-wide disable needs the signed channel and is increment 2 — until then an agent
  is disabled by its local break-glass file, which is stated rather than implied. The switch stops
  enforcement, not ingestion or retention. It does not revoke already-published response intents; those
  lapse on their own TTL.
