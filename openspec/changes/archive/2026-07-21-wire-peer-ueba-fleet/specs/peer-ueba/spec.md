# peer-ueba delta

## ADDED Requirements

### Requirement: peer-UEBA runs server-side over the verified fleet stream
The analyzer MUST be able to consume the control plane's VERIFIED telemetry stream, accumulating a
cross-fleet peer baseline from each verified event's pseudonymous subject, because a single endpoint
has no peers and the capability can only function where the whole fleet converges.

Only VERIFIED telemetry may move a baseline — an unverified or rejected message is not evidence
(D50) and MUST NOT influence any subject's peer-relative risk. The subject observed is the
pseudonymous id (D23), never a re-identified user.

#### Scenario: A verified outlier raises a peer alert; a typical subject does not
- **WHEN** the fleet analyzer is enabled and an outlier subject's activity crosses the peer-risk
  threshold while a typical subject stays near the peer mean
- **THEN** a peer alert is recorded for the outlier subject carrying its risk score and context
  version, and no alert is recorded for the typical subject
- **AND** a test asserts the discrimination end to end over the telemetry path

#### Scenario: Unverified telemetry does not move a baseline
- **WHEN** a message fails verification (bad signature, unknown/revoked agent, or replay)
- **THEN** it is rejected and the subject's peer baseline is unchanged
- **AND** a test asserts a rejected message contributes nothing to peer risk

### Requirement: peer-UEBA server-side detection never controls agents
The server-side integration MUST only produce investigations at the control plane and MUST NOT feed
risk back to agents or alter agent behaviour, preserving the observe-not-control boundary (D14).

The endpoint policy-Context seam (the `Dispatcher.ResolveContext` hook, D53) remains the core
integration point, but the running system uses peer-UEBA as a server-side detector; the two seams
are distinct and the fleet one does not close a control loop.

#### Scenario: A peer alert produces no agent-directed action
- **WHEN** the analyzer records a peer alert for a subject
- **THEN** the control plane persists a server-side detection only
- **AND** no message is sent to any agent and no agent behaviour changes as a result

### Requirement: server-side peer analysis is off by default
The fleet analyzer MUST be disabled unless explicitly enabled by operator configuration, so a
control plane does not silently profile a fleet without the consent/DPIA decision (D23).

#### Scenario: Disabled by default records nothing
- **WHEN** the control plane runs without peer-UEBA explicitly enabled
- **THEN** no subject is observed and no peer alert is ever recorded
- **AND** a test asserts the default control plane produces no peer alerts
