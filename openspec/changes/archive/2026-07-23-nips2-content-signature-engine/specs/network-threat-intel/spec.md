## ADDED Requirements

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
