## Why

Peer-UEBA (D54) produces individual alerts; a SIEM correlates them into INCIDENTS a human
acts on. Phase F2 adds the first correlation rule — a BURST: the same pseudonymous subject
tripping several alerts within a window is a stronger signal than any single alert.

## What Changes

- `CorrelationRule` (window, min-alerts, min-risk) + `Server.Correlate` — a parameterized
  GROUP BY / HAVING over peer_alerts producing `Incident`s (subject, count, max-risk,
  first/last seen), highest risk first; `/incidents` endpoint behind the operator gate.

## Capabilities

### Modified Capabilities
- `control-plane`: a correlation rule turns the alert aggregate into triageable incidents.

## Impact

- New `internal/controlplane/correlate.go`, `/incidents` under the operator gate;
  `docs/decisions.md` D104.
- Proven (Postgres): a subject with 4 alerts in the window correlates into one incident
  (count 4, max-risk the 0.99 peak, last-after-first); a single-alert subject and a subject
  whose alerts fall outside the window do NOT; raising the risk floor drops qualifying
  alerts below the count threshold and the incident disappears; /incidents is behind the
  operator gate (agent → 403). Guards mutation-tested (HAVING-threshold; window-cutoff;
  risk-floor-comparison).
- NOT in scope (stated): cross-HOST correlation (peer_alerts records subject + time but not
  the originating host; a host column adds that facet — a follow-up); multi-rule / stateful
  correlation chains; case creation from an incident (F3); the UI (F4). Correlates the
  content-free, pseudonymous fleet aggregate (D23/D54), never evidence (D10/D29); operator
  input bound as parameters (no SQL injection).
