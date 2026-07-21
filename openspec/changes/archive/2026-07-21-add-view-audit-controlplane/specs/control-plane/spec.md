## ADDED Requirements

### Requirement: Serving an investigation records who viewed it
When the control plane serves an investigation, it MUST record the view — viewer, what was queried,
and when — so that obtaining the evidence and leaving a record are one operation. The recorded
viewer MUST carry an identity marker and MUST be labelled unauthenticated until an authenticated
operator identity exists.

D20 requires the trail cover who VIEWED, not only who acted. The write surface that can record it is
the control plane (the CLI is a signer-less verifier, D30). Serving-and-recording atomically means a
caller cannot read the evidence without being logged. The unauthenticated label keeps a self-asserted
OS identity from being mistaken for a verified operator.

#### Scenario: A served investigation leaves a labelled view record
- **WHEN** an investigation is served through the control plane with a viewer identity
- **THEN** a view record is written carrying the viewer (labelled unauthenticated), what was queried,
  and the time, and the telemetry is returned
- **AND** a test asserts the record, the label, and that the view is readable back

#### Scenario: A bare, unlabelled viewer is refused
- **WHEN** a view is recorded with an empty viewer
- **THEN** it is rejected, so no unattributable view is silently recorded

### Requirement: The view log states its limits
The view log MUST be documented as non-evidentiary and its viewer as self-asserted — it is not the
forward-secure ledger, and the viewer is not authenticated.

A compromised control plane could alter or omit a view record, and the viewer is an OS identity, not
a verified operator. Presenting the view log as tamper-proof accountability would be the overclaim
the project forbids; the honest value is a recorded, readable trail of who looked, with its limits
named.

#### Scenario: No surface claims the view log is tamper-evident
- **WHEN** the view log is described
- **THEN** it is described as non-evidentiary with a self-asserted, unauthenticated viewer, and
  operator authentication is named as an unbuilt sibling gap
