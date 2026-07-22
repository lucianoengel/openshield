# control-plane (delta)

## MODIFIED Requirements

### Requirement: The control plane provides a bounded event search over the fleet aggregate
The control plane MUST provide a search over the received-telemetry aggregate that filters by
originating agent, kind, event id, a time window, and an attributable-only (verified) flag,
returning matching rows newest-first. The search MUST apply every operator-supplied constraint
as parameterized SQL (input as data, never concatenated), MUST hard-cap the number of rows
returned, and MUST return row metadata only — not the stored payload. The verified-only filter
MUST exclude self-asserted (unverified) telemetry, so an investigator can restrict a case to
attributable evidence. The search's read surface MUST be operator-gated AND MUST be reachable on
the served (mutual-TLS) router — a route registered internally but not mounted on the served mux
does not satisfy this.

#### Scenario: A filtered search returns only matching, attributable rows within the cap
- **WHEN** an operator searches the aggregate by agent, kind, or time window with the verified-only flag set
- **THEN** only rows matching every constraint are returned, newest-first, with self-asserted rows excluded, bounded by the row cap, and a malformed filter parameter is refused

#### Scenario: The event-search route is reachable and role-gated on the served mux
- **WHEN** an operator certificate requests the event-search route on the served mutual-TLS router, and an agent certificate requests it
- **THEN** the operator request is routed to the search (not a 404) and the agent request is refused with 403
