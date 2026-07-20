## ADDED Requirements

### Requirement: Policy receives enrichment as a resolved value
Pipeline `State` MUST carry the enrichment Context as a resolved value, not as an accessor or
provider interface, and it MUST be a closed typed set rather than a key-value map.

An accessor would let Policy perform an unbounded lookup — cache miss, lock, network call —
inside the fanotify permission window. An open map would be a surface through which a compromised
control plane could influence decisions by inventing keys a policy happens to read, which is the
threat the closed action set already closes for enforcement.

#### Scenario: Absent enrichment fails rather than defaults
- **WHEN** a policy requires an enrichment fact that is not present
- **THEN** evaluation fails explicitly
- **AND** no default value is substituted — a defaulted risk score reads as "safe" and would
  turn an analytics outage into a silent fail-open

### Requirement: State carries inert data only
Every field of pipeline `State` MUST be inert data. It SHALL NOT contain a function, interface
or channel field.

A callable field is a route by which a stage could reach the dispatcher, the registry or another
stage — the coupling the dispatcher design exists to prevent.

#### Scenario: A callable field on State fails the build
- **WHEN** a func, interface or channel field is added to State
- **THEN** the State field test fails
