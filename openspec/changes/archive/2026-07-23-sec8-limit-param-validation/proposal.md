## Why

SEC-8 established that a malformed operator query parameter is a 400, not a silent fall-back that yields
an over-broad result presented as authoritative. The `/search` filter params and the `/incidents`
correlation params (`min_alerts`, `window`, `min_risk`, …) already enforce it. But the `limit` param on
the two list endpoints — `GET /incidents` and `GET /alerts` — still uses `queryInt`, which SILENTLY
returns the default on a malformed or negative value (`?limit=abc`, `?limit=-5` → 100). An investigator
who fat-fingers a limit gets a truncated/defaulted list that looks authoritative, with no signal the
parameter was ignored. This finishes the SEC-8 rule on that last param.

## What Changes

- `GET /incidents` and `GET /alerts` validate `limit` with the same `intParam` helper the other params
  use: a non-integer or non-positive `limit` is a **400**, not a silent default. An absent `limit` keeps
  the default; an oversized `limit` stays accepted-and-clamped (the query layer already caps at
  `maxSearchLimit`).
- The silent-default `queryInt` helper is removed (both callers move to `intParam`), so the weak pattern
  cannot be reintroduced by copy.

## Capabilities

### Modified Capabilities
- `control-plane`: the malformed-parameter rule extends to the `limit` parameter on the operator list
  endpoints, not only the search filter.

## Impact

- `internal/controlplane/correlate.go` (`/incidents` handler), `internal/controlplane/operator_read.go`
  (`/alerts` handler; remove `queryInt`).
- No proto/core/schema change, no new dependency, no migration. Behavior change is narrow: a previously
  silently-defaulted bad `limit` now returns 400 (a stricter, more honest response).
