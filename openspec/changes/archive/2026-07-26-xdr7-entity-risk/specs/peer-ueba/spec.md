## ADDED Requirements

### Requirement: Risk is aggregated per entity across every domain

The system SHALL derive a risk score for an ENTITY from the alerts of all domains recorded for it within a
window, so a detection in one domain raises the risk a consumer in another domain applies.

The aggregation SHALL use the existing severity vocabulary rather than a second scale, and SHALL weight
recent alerts above older ones so a single old alert does not pin an asset at high risk indefinitely.

#### Scenario: An endpoint detection raises the risk a network consumer sees
- **WHEN** a high-severity endpoint alert is recorded for an entity and risk is recomputed
- **THEN** the risk published for that entity's subject rises above what it was
- **AND** the test FAILS if risk is derived from a single domain only

#### Scenario: Old alerts weigh less than recent ones
- **WHEN** two entities have the same alert severity but one's is old and the other's is recent
- **THEN** the recent one's risk is higher

### Requirement: Entity risk reaches every alias of the entity

Risk computed for an entity SHALL be published for each of that entity's aliases, so a consumer holding a
device pseudonym and one holding a user identity both receive it.

#### Scenario: A linked device and user both receive the entity's risk
- **WHEN** a device and a user alias are linked into one entity and risk is published for it
- **THEN** a consumer looking up either alias sees the risk

### Requirement: Cross-domain risk never lowers an existing signal

Publishing entity risk SHALL NOT reduce the risk a consumer already holds for a subject from another
source: the higher value SHALL win.

Turning cross-domain aggregation on must not be able to make a subject look SAFER than the behavioral
signal already says it is.

#### Scenario: A lower aggregate does not overwrite a higher existing risk
- **WHEN** a consumer holds a high risk for a subject and a lower entity risk is published
- **THEN** the consumer still applies the higher value
