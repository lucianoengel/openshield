## MODIFIED Requirements

### Requirement: The search endpoint rejects malformed filters and bounds the result size
The alert search endpoint MUST reject a malformed filter parameter with a client error rather
than silently ignoring it, so a bad value never yields an over-broad result presented as
authoritative. It MUST cap the result-set limit at a maximum, clamping a larger request rather
than allowing an unbounded query. The operator list endpoints (recent alerts and incidents) MUST
apply the same rule to their `limit` parameter: a malformed or non-positive `limit` MUST be a
client error, not a silent fall-back to the default, while an absent `limit` keeps the default and
an oversized `limit` is accepted and clamped to the maximum.

#### Scenario: A malformed filter is rejected and the limit is capped
- **WHEN** a search is requested with a malformed filter param or an oversized limit
- **THEN** the malformed param yields a client error, and the oversized limit is accepted but clamped to the maximum

#### Scenario: A malformed limit on a list endpoint is rejected
- **WHEN** the recent-alerts or incidents list endpoint is requested with a non-integer or non-positive `limit`
- **THEN** the endpoint returns a client error rather than silently applying the default limit

#### Scenario: An absent limit uses the default
- **WHEN** a list endpoint is requested with no `limit` parameter
- **THEN** the default limit is applied and the request succeeds
