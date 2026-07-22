# entity-graph-population Specification

## Purpose
The runtime producers that POPULATE the cross-domain entity graph (see `entity-model`), so a device
resolves to one entity across domains via real ingest — not an in-test derivation. Enrollment and
verified telemetry ingest resolve the device entity server-side; the gateway's dual-credential path
links device⋈user. Every write is a DERIVED-INDEX side effect (D38): best-effort, counted on failure,
never blocking or rolling back the primary action (enrollment, ingest, or an auth decision).


### Requirement: Enrollment populates the device entity

When an agent successfully enrolls, the control plane SHALL resolve a device entity for the agent's
canonical device pseudonym (`pseudonym.Of(agentID)`) in the XDR entity graph. The resolution SHALL be
best-effort: a graph failure SHALL be counted and logged but SHALL NOT fail the enrollment.

#### Scenario: A new agent enrolls
- **WHEN** an agent with id `A` enrolls with a valid token
- **THEN** `Resolve(KindDevice, pseudonym.Of("A"))` returns a stable entity id for that device
- **AND** the enrollment still succeeds even if the graph write fails

### Requirement: Verified telemetry ingest populates the device entity

When the control plane persists a VERIFIED `event`, it SHALL resolve a device entity for that event's
canonical subject (`Event.Subject.PseudonymousId`). The resolution SHALL be best-effort and SHALL NOT
change the ingest outcome for a persisted message.

#### Scenario: A verified event lands
- **WHEN** a signed `event` from agent `A` carrying subject `pseudonym.Of("A")` is verified and persisted
- **THEN** `Resolve(KindDevice, pseudonym.Of("A"))` returns an entity id for that device
- **AND** the id equals the one enrollment resolves for the same agent (two real producers converge)

#### Scenario: Ingest is unaffected by a graph error
- **WHEN** the entity-graph write for a persisted event fails
- **THEN** the event is still stored and the ingest outcome is still "persisted"
- **AND** the `EntityResolveFailures` counter increments

### Requirement: The gateway links device and user

The access proxy SHALL link the device and user aliases to the same entity
(`Link(KindDevice, deviceSubject, KindUser, userSubject)`) when it authenticates a request with BOTH a
device certificate and a verified OIDC user distinct from the device identity. The link SHALL run off
the request's critical path and SHALL NOT affect the auth decision or add request latency.

#### Scenario: A user authenticates on their device
- **WHEN** a request presents device cert `CN=A` and a valid OIDC token for user `U`
- **THEN** the device alias `pseudonym.Of("A")` and the user alias for `U` resolve to the SAME entity id
- **AND** the request's authorization outcome is identical whether or not the graph write succeeds

### Requirement: Graph population is derived, not authoritative

Entity-graph writes SHALL be treated as a derived index, never the system of record. A graph write
SHALL NEVER roll back or block the primary action (enrollment, ingest, or an auth decision), and a
failure SHALL be observable via a counter rather than surfaced as an error to the caller.

#### Scenario: Graph write failure is contained
- **WHEN** any entity `Resolve` or `Link` returns an error
- **THEN** the failure is counted and logged
- **AND** no primary action fails as a result
