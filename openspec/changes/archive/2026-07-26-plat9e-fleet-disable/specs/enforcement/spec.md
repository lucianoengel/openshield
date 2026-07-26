## ADDED Requirements

### Requirement: Fleet-wide operational control is a distinct, signed message type

Fleet-wide control SHALL use a vocabulary separate from response intents. Intent verbs cause enforcement;
this stops it, and one message type carrying both meanings fails in the most dangerous direction when a
consumer mishandles the discriminator.

#### Scenario: A signed disable stops enforcement on a consumer
- **WHEN** a consumer receives a validly signed, in-date, in-sequence disable
- **THEN** enforcement stops there, and detection continues

#### Scenario: A signed restore resumes enforcement
- **WHEN** a validly signed restore is received
- **THEN** enforcement resumes

### Requirement: A replayed control is refused

A consumer SHALL refuse a control whose sequence is at or below the highest it has applied. A captured,
genuinely signed disable verifies perfectly every time it is re-sent, so the signature alone cannot bound
it; without a sequence an attacker could re-disable a fleet after an operator restored enforcement.

#### Scenario: Re-sending a captured disable changes nothing
- **WHEN** a disable that was already applied is re-sent after a restore
- **THEN** it is refused and enforcement stays on

### Requirement: A control must be in date, in vocabulary, and verifiable

A control SHALL be refused if its signature does not verify, its version is unknown, its verb is
unspecified, or it is expired or carries no expiry. Every refusal SHALL leave enforcement ON.

#### Scenario: An unverifiable control changes nothing
- **WHEN** a control fails signature verification
- **THEN** enforcement is unchanged

#### Scenario: A control with no expiry is refused
- **WHEN** a control carries no expiry
- **THEN** it is refused, because a disable that cannot lapse is a product that is off with nobody
  remembering having turned it off

### Requirement: Publishing a fleet disable requires four-eyes

Publication of a fleet-wide disable SHALL require an approved four-eyes approval bound to that control's
id, with no exemption by impact class — there is no low-impact way to disable a security product
fleet-wide. The check SHALL happen before anything is signed or sent.

#### Scenario: An unapproved disable is never published
- **WHEN** no approved approval exists for the control id
- **THEN** nothing is signed or sent

#### Scenario: The approval binds to the exact control
- **WHEN** an approval is granted
- **THEN** it authorizes only the control whose id it names
