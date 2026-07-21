# packaging delta

## ADDED Requirements

### Requirement: A service catalog is parsed from configuration
The gateway MUST parse its internal-service catalog from a configuration string mapping service names to
upstream URLs, and MUST reject a malformed entry or an unparseable URL rather than silently skipping it,
so a misconfigured route fails loudly instead of leaving a service unexpectedly unreachable.

#### Scenario: A valid catalog resolves its services and a bad entry is rejected
- **WHEN** a catalog string of name=url pairs is parsed
- **THEN** each named service resolves to its upstream, and a malformed entry or bad URL is an error
