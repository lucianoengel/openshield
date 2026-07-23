# network-threat-intel Specification

## Purpose
The network signature / threat-intelligence engine (NIPS-2): it matches a flow against operator threat
intelligence on two axes — (1) destination/request METADATA against an IOC feed (known-bad domains,
IPs/CIDRs, URI substrings) and (2) the flow BODY against a content-signature ruleset (literal patterns
and regexes, matched in the sandboxed worker because the body is attacker content) — and records any
match as a distinct threat classification (its own axis from DLP content detection), so the policy can
prevent a flow to a known-bad indicator or one carrying a known-bad payload. This is what makes the
network plane an IPS rather than only a DLP inspector. The engine records a signal the policy acts on —
it never blocks on its own, and its absence never denies (fail open). Both the IOC feed and the
content-signature ruleset hot-reload without a restart; live remote-feed refresh is supported for the
IOC feed. Full Suricata/Snort rule grammar, multi-pattern optimization, response-body signature
scanning, and inline packet DROP are follow-ups.


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

### Requirement: Content-signature matching over the flow body in the sandboxed worker

The system SHALL match a network flow's BODY against an operator-loaded content-signature ruleset, and
this matching SHALL run in the sandboxed parser worker — never in the network-capable gateway process —
because the body is attacker-controlled content. Each signature rule SHALL carry an id, one or more
literal content patterns (each optionally case-insensitive), an optional regular expression, a closed
threat category, and a confidence; a rule matches a body only when ALL of its literal patterns are
present AND its regular expression (if any) matches. The engine SHALL scan under a bounded budget so a
large or adversarial body cannot exhaust memory or hang; exceeding the budget SHALL degrade to matching
what was scanned (fail-open), never an error or a stall. A recorded content-signature match SHALL carry
only the rule id, category, and confidence and SHALL NOT place the matched bytes into the classification
or across the worker IPC boundary. A malformed ruleset entry SHALL fail to load with an error; an absent
ruleset SHALL leave the content-signature engine inert (no matches, no error).

#### Scenario: A body carrying a signature pattern is flagged
- **WHEN** a flow's body contains a rule's literal pattern (and its regex, if any, matches)
- **THEN** the worker records a content-signature threat match for the flow, carrying the rule id and category but not the matched bytes

#### Scenario: A clean body is not flagged
- **WHEN** a flow's body matches no rule in the ruleset
- **THEN** the worker records no content-signature match and the flow is not flagged by the engine

#### Scenario: An oversized body is bounded, not hung
- **WHEN** a flow's body exceeds the content-signature scan budget
- **THEN** the scan terminates within the budget and the flow is classified without a hang or memory exhaustion

#### Scenario: A malformed ruleset fails to load
- **WHEN** the content-signature ruleset has an unparseable entry
- **THEN** loading the ruleset returns an error and the engine does not silently drop the rule

### Requirement: Policy can prevent a flow on a content-signature match

The system SHALL expose a content-signature match to the policy as a threat match on the same axis the
IOC metadata matches use, so a policy rule can prevent a flow whose body trips a signature. When a flow
produces BOTH an IOC metadata match and a content-signature match, the policy SHALL see both — recording
one kind of threat match MUST NOT discard the other. The content-signature engine itself MUST NOT block
a flow, and its absence MUST NOT deny a flow (fail open).

#### Scenario: A policy blocks a flow whose body trips a signature
- **WHEN** a policy that blocks on a threat match evaluates a flow the content-signature engine flagged
- **THEN** the decision is to block the flow

#### Scenario: A metadata match and a content match coexist on one flow
- **WHEN** a single flow matches both an IOC indicator and a content signature
- **THEN** the policy sees both threat matches, neither overwriting the other

#### Scenario: The content-signature engine never denies on its own
- **WHEN** no ruleset is configured or a body matches nothing
- **THEN** the flow carries no content-signature match and the engine does not by itself deny it

### Requirement: The content-signature ruleset hot-reloads without a restart

The system SHALL reload the content-signature ruleset when its file changes, so a new signature takes
effect without restarting the worker, swapping the running ruleset atomically (in-flight scans keep the
ruleset they read; the next scan sees the new one). A changed-but-malformed ruleset SHALL be reported and
the current ruleset KEPT — a ruleset edit that fails to parse MUST NOT disarm the running engine. The
initial ruleset baseline SHALL be established synchronously when the watcher is constructed, so a body
scanned immediately after startup cannot race an unread ruleset.

#### Scenario: A new signature takes effect after an edit
- **WHEN** the ruleset file is edited to add a signature and the reload interval elapses
- **THEN** a subsequent flow whose body trips that signature is flagged, with no worker restart

#### Scenario: A malformed edit is served-stale
- **WHEN** the ruleset file is changed to a version that fails to parse
- **THEN** the error is reported and the previously-loaded ruleset keeps serving
