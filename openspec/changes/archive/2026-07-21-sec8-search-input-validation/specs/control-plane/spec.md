# control-plane delta

## ADDED Requirements

### Requirement: The search endpoint rejects malformed filters and bounds the result size
The alert search endpoint MUST reject a malformed filter parameter with a client error rather
than silently ignoring it, so a bad value never yields an over-broad result presented as
authoritative. It MUST cap the result-set limit at a maximum, clamping a larger request rather
than allowing an unbounded query.

#### Scenario: A malformed filter is rejected and the limit is capped
- **WHEN** a search is requested with a malformed filter param or an oversized limit
- **THEN** the malformed param yields a client error, and the oversized limit is accepted but clamped to the maximum
