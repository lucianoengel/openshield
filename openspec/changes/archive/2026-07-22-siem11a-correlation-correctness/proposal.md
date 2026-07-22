# SIEM-11a: correlation correctness — legacy-host count + param validation

## Why

Two correctness bugs in the correlation surface (the smaller half of SIEM-11, ahead of incident
materialization):
- **False lateral movement**: `count(DISTINCT agent_id)` counts a legacy/pre-identity alert's empty
  `agent_id` (`''`) as a distinct host, so a subject with ONE real host plus pre-identity alerts
  falsely reaches a cross-host threshold (`MinHosts ≥ 2`) — a fabricated "lateral movement" signal.
- **Silent over-broadening**: `/incidents` and `/overdue` silently ignore a malformed
  `window`/`min_risk`/`min_alerts`/`min_hosts`/`threshold` and fall back to the default — the SEC-8
  "a wrong answer looks authoritative" failure, unapplied on these two routes.

## What Changes

- **`count(DISTINCT NULLIF(agent_id, ''))`** in the correlation query — an empty host is not a
  distinct host, so the cross-host count reflects real hosts only.
- **`/incidents` and `/overdue` reject a malformed param with 400** (like `/search`), via a
  fail-loud `intParam` helper and explicit duration/float parsing.

This modifies the `control-plane` capability.

## Impact

- Affected specs: `control-plane`
- Affected code: `internal/controlplane/correlate.go`, `internal/controlplane/operator_read.go`.
- Not in scope (stated): materializing incidents into a persisted table with id/state so an ack or
  case can target an incident as a unit (SIEM-11b — the larger half); a multi-rule correlation
  engine beyond burst + host-count.
