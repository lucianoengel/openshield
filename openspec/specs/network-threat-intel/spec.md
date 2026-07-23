# network-threat-intel Specification

## Purpose
The network signature / threat-intelligence engine (NIPS-2): it matches a flow's destination and
request metadata against an operator-loaded IOC feed — known-bad domains, IPs/CIDRs, and URI
substrings — and records any match as a distinct threat classification (its own axis from DLP content
detection), so the policy can prevent a flow to a known-bad indicator. This is what makes the network
plane an IPS rather than only a DLP inspector. It matches metadata only (never the body); YARA-style
body-content signatures and live feed refresh are follow-ups. The engine records a signal the policy
acts on — it never blocks on its own, and its absence never denies (fail open).


### Requirement: Threat-intel matching over flow metadata

The system SHALL match a network flow's destination and request metadata against an operator-loaded IOC
feed — known-bad domains (exact and parent-suffix), IP addresses (exact and CIDR), and URI substrings —
and record any match as a threat classification carrying a closed category and a confidence, without
placing the matched content into the classification. A configured feed with a malformed entry MUST fail
to load with an error; an absent feed MUST leave the engine inert (no matches, no error).

#### Scenario: A flow to a known-bad domain is flagged

- **WHEN** a flow's host is, or is a subdomain of, a domain on the IOC feed
- **THEN** the engine records a domain threat match for the flow

#### Scenario: A flow to a known-bad IP is flagged

- **WHEN** a flow's destination IP is a feed IP or falls in a feed CIDR
- **THEN** the engine records an IP threat match for the flow

#### Scenario: A clean flow is not flagged

- **WHEN** a flow's host, IP, and path match nothing on the feed
- **THEN** the engine records no threat match

#### Scenario: A malformed feed fails to load

- **WHEN** the IOC feed has an unparseable entry
- **THEN** loading the feed returns an error

### Requirement: Policy can prevent a flow on a threat match

The system SHALL expose recorded threat matches to the policy so a rule can block a flow to a known-bad
indicator. The threat engine itself MUST NOT block — it records a signal the policy acts on — and its
absence MUST NOT deny a flow (fail open).

#### Scenario: A policy blocks a flow to a known-bad destination

- **WHEN** a policy that blocks on a threat match evaluates a flow the engine flagged
- **THEN** the decision is to block the flow

#### Scenario: The threat engine never denies on its own

- **WHEN** no feed is configured or a flow matches nothing
- **THEN** the flow carries no threat match and the threat engine does not by itself deny it

### Requirement: The IOC feed hot-reloads without a restart

The system SHALL reload the IOC feed when its file changes, so a new indicator takes effect without
restarting the gateway, and the running feed SHALL be swapped atomically (in-flight flows keep the feed
they read; the next flow sees the new one). A changed-but-malformed feed SHALL be reported and the
current feed KEPT — a feed edit that fails to parse MUST NOT disarm the running engine.

#### Scenario: A new indicator takes effect after an edit

- **WHEN** the IOC feed file is edited to add an indicator and the reload interval elapses
- **THEN** a subsequent flow to that indicator is flagged, with no gateway restart

#### Scenario: A malformed edit is served-stale

- **WHEN** the IOC feed file is changed to a version that fails to parse
- **THEN** the error is reported and the previously-loaded feed keeps serving

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
