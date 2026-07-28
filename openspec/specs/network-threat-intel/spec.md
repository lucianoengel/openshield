

## Purpose

Threat detection over network metadata: operator IOC feeds (file or URL, signed, with verification
BEFORE parsing and refusal of a bad feed as a WHOLE), content signatures matched on the flow body inside
the sandboxed worker, and destination-agnostic beaconing detection that finds a rhythm without prior
knowledge of the destination. Rulesets and feeds hot-reload, a bad edit is served-stale, only VERIFIED
telemetry contributes, and a finding carries its evidence without enforcing on its own.

## Requirements

### Requirement: Regular contact with a destination is detected without prior knowledge of it

The system SHALL detect destinations contacted at regular intervals by one subject, without requiring the
destination to appear in any feed or signature. This is the network signal that survives when the
destination is unknown, the payload is encrypted and the volume is trivial.

#### Scenario: A regular check-in is reported
- **WHEN** a subject contacts one destination at consistent intervals often enough to measure
- **THEN** a finding is reported for that destination

#### Scenario: Irregular traffic is not reported
- **WHEN** a subject's contacts with a destination are irregularly spaced
- **THEN** no finding is reported

#### Scenario: Too few contacts are not a rhythm
- **WHEN** there are too few contacts to measure regularity
- **THEN** no finding is reported, because a handful of intervals is always "regular"

### Requirement: Detection tolerates jitter and a missed check-in

Regularity SHALL be measured so that configured jitter and an occasional missed or delayed contact do not
hide a beacon. Every C2 framework offers jitter, so a detector that only catches perfect metronomes catches
only the misconfigured.

#### Scenario: A jittered beacon with one long outage is still found
- **WHEN** contacts are regular within a jitter margin and one gap is far longer than the rest
- **THEN** the finding is still reported

### Requirement: A rhythm belongs to one subject and one destination

Contacts SHALL be grouped per subject. Pooling a fleet's contacts to a shared destination would synthesize
a rhythm no endpoint exhibits — many hosts polling the same service at staggered offsets look, in
aggregate, like a metronome.

#### Scenario: A fleet's staggered polling is not a beacon
- **WHEN** many subjects each contact one destination a few times at staggered offsets
- **THEN** no finding is reported

### Requirement: Only verified telemetry contributes

Beaconing SHALL be derived only from verified events. It is inferred purely from timing, so unverified
telemetry could otherwise fabricate a beacon against any destination, or bury a real one.

#### Scenario: Unverified flows produce nothing
- **WHEN** the only matching flows are unverified
- **THEN** no finding is reported

### Requirement: A finding carries its evidence and does not enforce

A finding SHALL carry the interval, contact count and a regularity measure, and SHALL NOT trigger
enforcement. Legitimate software beacons constantly, so a finding must be dismissible at a glance and must
never act on its own.

#### Scenario: The finding is dismissible
- **WHEN** a beacon is reported
- **THEN** its interval, count and regularity are available with it

#### Scenario: Allowlisted destinations are never reported
- **WHEN** a destination is allowlisted
- **THEN** it produces no finding, while other destinations still do

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

<!-- restored from 2026-07-22-nips2-remote-feed-pull -->

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

<!-- restored from 2026-07-22-nips2-threat-intel-engine -->

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

<!-- restored from 2026-07-22-nips2-threat-intel-engine -->

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

<!-- restored from 2026-07-23-nips2-content-signature-engine -->

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

<!-- restored from 2026-07-23-nips2-content-signature-engine -->

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

<!-- restored from 2026-07-23-nips2-content-signature-engine -->

### Requirement: An IOC feed may be signed, and verification precedes parsing

The feed loader SHALL support a detached ed25519 signature over the feed's exact bytes. When a
verification key is supplied, the signature SHALL be checked **before** any byte of the feed is parsed,
and a failed check SHALL reject the entire feed. The parser is the untrusted-input surface: verifying
after parsing would mean a hostile feed had already been through it, and rejecting per-line would apply
the attacker-chosen subset that verified.

#### Scenario: An unsigned load path stays available
- **WHEN** no verification key is supplied
- **THEN** the feed loads as before, and the deployment's lack of feed authentication is a configuration
  choice rather than a silent default

#### Scenario: A bad signature rejects the feed before parsing
- **WHEN** a verification key is supplied and the signature does not check out
- **THEN** the load fails, no feed is returned, and the content is not parsed

<!-- restored from 2026-07-26-soar5-signed-ti-enrichment -->

### Requirement: A feed's format is named, never sniffed

The loader SHALL accept the native line format and a CSV format, selected by an explicit format name.
Detecting the format from the content would let a crafted file choose the parser it is handled by.

#### Scenario: An explicit format is honoured
- **WHEN** a feed is loaded with a named format
- **THEN** it is parsed by that format's parser, and content that is invalid for it is an error

<!-- restored from 2026-07-26-soar5-signed-ti-enrichment -->

### Requirement: A parsed feed's indicators are enumerable and reconstructable

A feed SHALL expose the indicators it holds, and SHALL be constructible from a list of indicators, so a
consumer can persist a feed and later rebuild the identical matcher. This is what keeps matching to one
implementation instead of one per consumer.

#### Scenario: A feed round-trips through its indicator list
- **WHEN** a feed's indicators are enumerated and used to build a new feed
- **THEN** the rebuilt feed matches exactly the same observables as the original

<!-- restored from 2026-07-26-soar5-signed-ti-enrichment -->
