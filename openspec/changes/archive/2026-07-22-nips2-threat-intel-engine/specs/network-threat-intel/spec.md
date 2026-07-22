## ADDED Requirements

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
