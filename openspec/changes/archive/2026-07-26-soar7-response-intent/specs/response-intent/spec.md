## ADDED Requirements

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
