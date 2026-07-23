## ADDED Requirements

### Requirement: The transparent redirect self-heals to direct resolution when the resolver fails

When the transparent DNS redirect is active, the system SHALL continuously probe the local resolver's
liveness and, after a threshold of consecutive failed probes, SHALL remove the redirect so that host DNS
falls back to direct resolution rather than being wedged against a dead resolver. A single failed probe
MUST NOT remove the redirect (the threshold damps flapping). When the resolver recovers, the system SHALL
re-install the redirect. On shutdown the redirect MUST be removed. This is the fail-open availability
invariant applied to the redirect itself: a failure of the control must get out of the way, never take the
host's name resolution down with it.

#### Scenario: A wedged resolver is bypassed, not left wedging DNS
- **WHEN** the resolver stops answering and the failed-probe threshold is reached
- **THEN** the redirect is removed and subsequent DNS queries resolve directly instead of being dropped into the dead resolver

#### Scenario: A single failed probe does not bypass
- **WHEN** the resolver fails a single liveness probe but is answering again on the next
- **THEN** the redirect stays installed (the threshold prevents flapping)

#### Scenario: The redirect is restored when the resolver recovers
- **WHEN** the resolver was bypassed and then answers a liveness probe again
- **THEN** the redirect is re-installed so unconfigured clients are covered again
