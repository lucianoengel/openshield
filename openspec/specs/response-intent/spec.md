

## Purpose

Coordinated response as an INTENT rather than a command: the server publishes a signed, versioned,
time-bounded intent from a closed vocabulary, and each domain enacts it independently — the server never
tells an agent what to do. Every enactment is traceable to the intent that caused it, expiry releases
every domain, and a high-impact intent requires a second operator and a bounded blast radius.

## Requirements

### Requirement: One intent is enacted independently by every consuming domain

The system SHALL allow a single response intent to be consumed by more than one domain, each deciding with
its OWN local policy — so one approved containment can block an entity's network flows and refuse its
executions at the same time, without either domain being commanded by the control plane.

Containment MAY therefore be PARTIAL: a domain whose policy does not read intents enacts nothing and
reports nothing unusual. That SHALL be stated rather than implied away, because a half-enacted containment
looks identical to a whole one from the control plane's side.

#### Scenario: One containment is enacted in two domains
- **WHEN** a containment intent is in effect for an entity
- **THEN** the network domain refuses that entity's flows and the endpoint domain refuses its executions,
  each by its own policy

#### Scenario: Neither domain acts before an intent exists
- **WHEN** no intent is in effect
- **THEN** both domains decide as they would without the capability

### Requirement: Every enactment of one intent is traceable to that intent

Each enactment SHALL record the identity of the intent that produced it, so two decisions in different
domains can be correlated as enactments of ONE containment rather than two unrelated verdicts.

The identity SHALL be carried in the field that already records which enrichment context applied to a
decision, and which is already written to the audit ledger. Adding a new hashed ledger column for this
purpose SHALL be avoided: the ledger is a hash chain, and a new hashed column breaks continuity at the point
of change.

#### Scenario: Both enactments carry the same intent identity
- **WHEN** two domains enact the same containment
- **THEN** both decisions record the same intent identity
- **AND** the test FAILS if the identity is not stamped, leaving the two enactments uncorrelatable

### Requirement: Expiry releases every domain

When an intent expires, EVERY domain that was enacting it SHALL return to its uncontained behaviour.

A containment that cannot lapse is a permanent quarantine, and one that lapses in some domains but not
others leaves an asset in a state no operator asked for.

#### Scenario: Both domains are released on expiry
- **WHEN** a containment intent's expiry passes
- **THEN** the network domain allows the entity's flows again and the endpoint domain allows its executions
- **AND** the test FAILS if expiry is ignored on read

### Requirement: An operator can publish a response intent

The response-intent producer SHALL be reachable by an authenticated operator. A consumer that verifies
intents while nothing can publish one provides no capability.

Publication SHALL send exactly the intent that was prepared and, for a high-impact verb, exactly the one
that was approved. An approval SHALL NOT be invalidated by the passage of time between the approval and
the publication it authorizes.

The publication surface SHALL accept multiple subjects in one request, so that the blast-radius ceiling
is reachable. A ceiling that can never bind is not a control.

#### Scenario: A high-impact intent needs a second operator
- **WHEN** an operator prepares a high-impact intent and attempts to publish it unapproved
- **THEN** nothing is published

#### Scenario: The approved intent is the published intent
- **WHEN** an approved intent is published after the issuing minute has elapsed
- **THEN** it publishes, carrying the approved id

#### Scenario: An over-broad publication is refused as a whole
- **WHEN** a publication targets more subjects than the ceiling
- **THEN** it is refused and no intent reaches the broker

### Requirement: The intent vocabulary is closed and the server never commands

A response intent SHALL carry a verb from a CLOSED set — elevate-scrutiny, contain, revoke-trust — and
SHALL NOT be able to express an arbitrary action. It SHALL be delivered as DATA that a consumer's LOCAL
policy interprets, never as an instruction the consumer executes.

A consumer whose policy does not read intents SHALL be unaffected by them.

#### Scenario: An intent is policy context, not a command
- **WHEN** an intent is delivered to a consumer whose policy ignores intents
- **THEN** the consumer's behavior is unchanged

#### Scenario: The vocabulary cannot express an arbitrary action
- **WHEN** the intent verb set is enumerated
- **THEN** it contains exactly the three closed verbs, and adding one is a deliberate edit that a test
  requires

<!-- restored from 2026-07-26-soar7-response-intent -->

### Requirement: An intent is signed, versioned and time-bounded

An intent SHALL be signed by the control plane, and a consumer SHALL reject one whose signature does not
verify. An unsigned intent SHALL NOT be published at all.

An intent SHALL carry an expiry, and a consumer SHALL treat an expired intent as absent. An intent whose
version is not understood SHALL be rejected rather than partially applied.

A `contain` with no expiry would be a permanent quarantine nobody remembers issuing.

#### Scenario: A forged intent is rejected and counted
- **WHEN** an intent arrives whose signature does not verify against the control-plane key
- **THEN** it is rejected, counted, and does not become policy context
- **AND** the test FAILS if an unverified intent is applied

#### Scenario: An expired intent is not in effect
- **WHEN** an intent's expiry has passed
- **THEN** a consumer reads no intent for that subject

#### Scenario: An unsigned intent is never published
- **WHEN** publication is attempted with no signing key configured
- **THEN** nothing is published

<!-- restored from 2026-07-26-soar7-response-intent -->

### Requirement: A high-impact intent requires a second operator and a bounded blast radius

Publishing a high-impact intent (contain, revoke-trust) SHALL require an approved four-eyes approval for
that specific intent, and SHALL be refused when the number of targeted subjects exceeds a configured
ceiling.

The ceiling exists because the failure that matters is not one wrong containment but a fleet-wide one: an
operator error or a compromised control plane reaching every device at once.

#### Scenario: An unapproved high-impact intent is not published
- **WHEN** a contain intent is published without an approved approval for it
- **THEN** publication is refused and no intent is delivered
- **AND** the test FAILS if the intent is published anyway

#### Scenario: An intent beyond the blast radius is refused
- **WHEN** an intent targets more subjects than the configured ceiling
- **THEN** it is refused before publication

#### Scenario: A low-impact intent needs no approval
- **WHEN** an elevate-scrutiny intent is published
- **THEN** it is published without requiring an approval

<!-- restored from 2026-07-26-soar7-response-intent -->
