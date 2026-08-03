## ADDED Requirements

### Requirement: A decision carries the ATT&CK techniques its evidence supported

A Decision SHALL carry the MITRE ATT&CK technique ids derived from the signals the decision was made
over. Those ids SHALL come from the platform's own signal derivation — the same derivation supplied to
policy as input — and SHALL NOT be read out of the policy result.

A policy module is operator-authored text. If a rule could declare a technique, then "what did this
asset evidence?" would be answered by whatever the rules asserted, and technique-level correlation
would correlate claims rather than signals.

An empty technique list is a real answer ("no signal mapped to a technique"), not a missing one.

#### Scenario: The derivation reaches the decision
- **WHEN** a credential is written to a cloud-sync path and the policy decides
- **THEN** the decision carries exactly the technique ids the signals evidence, and satisfies the
  decision contract

#### Scenario: A policy cannot declare a technique
- **WHEN** a policy module returns a result containing technique ids, over an event whose signals map
  to no technique
- **THEN** the decision carries no techniques

### Requirement: The decision contract refuses a technique outside the vocabulary

The decision contract SHALL reject a decision carrying any technique id that is not a member of the
closed vocabulary, and a rejected decision SHALL NOT be projected into the alert stream at all — not
projected with the offending field stripped.

Signature verification establishes who sent a decision, not that what they sent is expressible in the
platform's contract. These ids are what operators hunt over, so an enrolled-but-compromised producer
that could write arbitrary ids could manufacture an attack chain no signal evidenced.

#### Scenario: A forged technique does not reach the alert stream
- **WHEN** a verified producer publishes a decision carrying a technique id this build cannot derive
- **THEN** a contract violation is counted, no alert is written for that decision, and no alert in the
  stream carries the forged id

#### Scenario: A well-formed decision's techniques are persisted
- **WHEN** a decision carrying vocabulary-member technique ids is projected
- **THEN** the resulting unified alert carries exactly those ids

### Requirement: A correlation rule may name an ordered technique sequence

The cross-domain rule SHALL accept an optional ordered sequence of ATT&CK technique ids that an
entity's alerts must contain as an ordered subsequence, composing with — not replacing — the domain
sequence. Both constraints SHALL hold when both are given.

Two steps of a technique sequence SHALL NOT be satisfied by the same alert. An alert may carry several
techniques, but a sequence is an ordering claim and one alert is one moment: it cannot evidence "then".

An alert carrying no technique SHALL NOT satisfy any step.

Each correlated incident SHALL report the distinct techniques its contributing alerts carried, in
first-seen order.

#### Scenario: The chain matches and its permutations do not
- **GIVEN** three entities that all satisfy the plain cross-domain rule, one evidencing T1552 then
  T1567.002 on separate alerts, one the reverse order, and one carrying both on a single alert
- **WHEN** the rule is run with the technique sequence T1552 then T1567.002
- **THEN** only the first entity raises an incident, and that incident reports both techniques

#### Scenario: An entity with no techniques is not swept in
- **GIVEN** an entity whose alerts carry no techniques and which correlates under the plain rule
- **WHEN** any technique sequence is requested
- **THEN** that entity raises no incident

### Requirement: A technique sequence naming an underivable id is refused

A correlation request whose technique sequence names an id outside the vocabulary SHALL be rejected
with a client error naming the offending id, never silently accepted.

A step no producer can emit would never match, and the operator would read the resulting empty list as
"that attack chain did not happen".

#### Scenario: An unknown technique is a 400
- **WHEN** an operator requests a technique sequence containing an invented id, a real ATT&CK id this
  build cannot derive, the parent of a derived sub-technique, or a differently-cased id
- **THEN** the request is rejected with a client error quoting the id

#### Scenario: A well-formed technique sequence is served
- **WHEN** an operator requests a valid technique sequence over the correlation endpoint
- **THEN** the response lists the matching incidents, each carrying its techniques

### Requirement: Replay compares a decision's techniques

Decision replay SHALL compare the technique list, including its order, and report a difference as a
divergence.

The techniques are a deterministic derivation of the same signals the policy saw, so a replay that
reproduces the action but not the techniques is a real divergence. Excluding them would leave the
field operators hunt over unable to be proven derived rather than asserted.

#### Scenario: A technique difference is a divergence
- **WHEN** two decisions agree on every other compared field but differ in the presence, absence,
  identity or order of a technique
- **THEN** replay reports a divergence
