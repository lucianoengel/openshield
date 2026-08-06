# enforcement

## ADDED Requirements

### Requirement: The enforcement acknowledgement is projected from the path agents publish on

The acknowledgement SHALL be projected from the transport an agent actually uses. A projection reachable
only from a transport with no producer SHALL NOT be considered wired.

Every producer signs its telemetry, and the acknowledgement was projected only from the unsigned
heartbeat subject, which nothing publishes to. The signed path received every heartbeat, stored it and
discarded its enforcement fields — so the table PLAT-9 reads was written by nothing but tests, and "did
my fleet disable arrive?" returned an empty result on every deployment that has ever run.

#### Scenario: A signed heartbeat updates the acknowledgement
- **WHEN** an enrolled agent publishes a signed heartbeat reporting its enforcement state
- **THEN** the fleet acknowledgement reflects that state

#### Scenario: An unverifiable heartbeat cannot move the acknowledgement
- **WHEN** a heartbeat fails verification
- **THEN** the recorded acknowledgement is unchanged, so a forged "already disabled" cannot hide a live
  endpoint from an operator trying to stop it
