## Why

The operator read API (D82) returned only the N most recent peer alerts — no way to
investigate. Phase F (SIEM depth) begins with F1: a filtered search over the fleet-alert
aggregate (by subject, risk, time window), the query substrate a SIEM UI and correlation
build on. The security constraint: operator input must be DATA, never SQL.

## What Changes

- `AlertFilter` (subject, min-risk, since, until, limit) + `Server.SearchPeerAlerts` —
  builds a PARAMETERIZED WHERE clause from only the set constraints (each bound as a
  placeholder, never concatenated); `/search` endpoint behind the operator-role gate (D58).

## Capabilities

### Modified Capabilities
- `control-plane`: the operator read surface gains a filtered fleet-alert search.

## Impact

- `internal/controlplane/operator_read.go` (+SearchPeerAlerts, /search), `enroll_http.go`
  (mount /search under the operator gate); `docs/decisions.md` D103.
- Proven (Postgres): filtering by subject, by minimum risk (with the comparison verified —
  no low-risk leaks), by combined subject+risk, and by time window each return the right
  rows; an injection-shaped subject (`'; DROP TABLE peer_alerts; --`) is treated as DATA —
  it matches nothing and the table is intact afterward; /search is behind the operator gate
  (an agent role gets 403). Guards mutation-tested (subject-filter-dropped; min-risk-≥-
  flipped; since-filter-dropped).
- NOT in scope (stated): full-text search over event payloads (peer alerts carry no content
  by design, D54 — this searches the fleet-derivation aggregate, not raw evidence);
  cross-host correlation/rules (F2); casework (F3); the UI (F4); syslog ingest (F5).
  Read-only, forge-nothing (the handler holds no signer, D30); pseudonymous subjects (D23).
