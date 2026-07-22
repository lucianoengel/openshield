## Why

SEC-8 (P2). `/search` silently dropped malformed `since`/`until`/`min_risk` params — yielding
OVER-BROAD results that look authoritative (an investigator trusts a wrong answer) — and
`limit` had no upper bound (an unbounded query / memory vector). SQL injection is already
correctly parameterized (D103); this fixes input validation.

## What Changes

- `parseAlertFilter` — parses the /search params, returning an error on ANY malformed value
  (→ 400) instead of silently dropping it, and caps `limit` at `maxSearchLimit` (1000).
- `SearchPeerAlerts` also clamps the limit (defense in depth for a direct caller).

## Capabilities

### Modified Capabilities
- `control-plane`: /search rejects malformed filters and bounds the result size.

## Impact

- `internal/controlplane/operator_read.go`; `docs/decisions.md` D119.
- Proven (HTTP, operator-gated): a malformed `min_risk`/`since`/`until`/`limit` → 400; a
  well-formed search → 200; an oversized `limit` is accepted and CAPPED (not rejected — a big
  ask is honored up to the cap); the existing injection test stays green. Guards mutation-
  tested (min_risk/since silently dropped; limit not validated — each then fails to 400).
- NOT in scope (stated): a configurable cap (hard-coded 1000 for now — PLAT-5 config surface);
  pagination cursors (a follow-up when result sets grow). The SQL is already parameterized
  (D103) and stays that way.
