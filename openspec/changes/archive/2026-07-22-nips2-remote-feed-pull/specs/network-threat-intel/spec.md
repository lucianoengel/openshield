## ADDED Requirements

### Requirement: The IOC feed can be pulled from a remote URL

The system SHALL be able to fetch the IOC feed from an operator-configured URL on a timer, in addition
to a local file, and hot-swap it atomically on change (in-flight flows keep the feed they read). The
fetch SHALL be bounded in size and SHALL use a conditional request so an unchanged feed is not
re-downloaded or re-parsed. A fetch or parse FAILURE SHALL serve-stale — the current feed keeps serving
— so a feed-server outage or a bad publish never disarms the running engine.

#### Scenario: A remote feed change takes effect
- **WHEN** the feed served at the configured URL is changed to add an indicator and the reload interval elapses
- **THEN** a subsequent flow to that indicator is flagged, with no gateway restart

#### Scenario: An unchanged feed is not re-parsed
- **WHEN** the feed URL returns "not modified" for a conditional request
- **THEN** the current feed continues to serve and no re-parse occurs

#### Scenario: A feed-server failure serves stale
- **WHEN** the feed URL is unreachable or returns an unparseable body during a refresh
- **THEN** the failure is reported and the previously-loaded feed keeps serving
