## ADDED Requirements

### Requirement: An approval records what four-eyes was worth when it was resolved

Resolving an approval SHALL record the operator-identity assurance in force at that moment, and the
recorded value SHALL be readable alongside the approval.

The approver≠requester comparison is sound. What it compares is an identity STRING, and two deployment
switches decide what one is worth: whether an identity with no server-side record falls back to the role
in its certificate, and whether an operator bearer token that is not sender-constrained is accepted.
With either off, two credentials can be two "operators" — and the credentials need not correspond to two
people, or to anyone the deployment has a record of.

Without this the trail says only "alice requested, bob approved", which reads as two people whatever the
deployment could actually distinguish. **An audit record attesting to a control that did not exist is
worse than declining to offer the control**, because the record is what an investigation later relies
on.

The value SHALL be recorded at RESOLUTION, not derived when the approval is read. It is a fact about the
moment the approval happened: a deployment that hardens later must not retroactively make earlier
approvals look strong, and one that loosens must not make them look weak.

#### Scenario: An approval on an unhardened deployment is recorded as weak
- **WHEN** an approval is resolved while either operator-identity switch is off
- **THEN** the approval records weak assurance, and the approval itself still succeeds

#### Scenario: An approval on a hardened deployment is recorded as strong
- **WHEN** both switches are on and an approval is resolved
- **THEN** the approval records strong assurance

### Requirement: A deployment may refuse to grant an approval it cannot attest to

A deployment SHALL be able to require hardened operator identity for approvals, in which case granting
one while identity is unhardened SHALL be REFUSED and the request SHALL remain pending.

DENIALS SHALL never be gated. Refusing to record a "no" would leave the pending request — a
containment, a fleet-wide disable, a case closure — alive and approvable, and would block the operator
trying to shut it down. A hardening control must not become a way of keeping dangerous things pending.

#### Scenario: A weak approval is refused and the request stays pending
- **WHEN** a deployment requires strong assurance and an operator grants an approval while identity is
  unhardened
- **THEN** the grant is refused, naming the unhardened switches, and the request is still pending

#### Scenario: A denial lands regardless of assurance
- **WHEN** the same deployment DENIES the request
- **THEN** the denial succeeds and is recorded, carrying the weak assurance

### Requirement: A component states what its four-eyes is worth at startup

A component offering a four-eyes control SHALL state, at startup and without being asked, whether
operator identity is hardened, and SHALL NAME each switch that is not.

A warning that says identity is weak without naming the setting to change is a warning that gets
acknowledged and left alone. The confirmation SHALL also be printed when identity IS hardened: a message
that appears only on failure cannot be used to verify success.

#### Scenario: An unhardened deployment names its gaps
- **WHEN** a component starts with either operator-identity switch off
- **THEN** it reports weak four-eyes assurance and names each switch that is off

#### Scenario: A hardened deployment is told so
- **WHEN** both switches are on
- **THEN** it reports strong four-eyes assurance
