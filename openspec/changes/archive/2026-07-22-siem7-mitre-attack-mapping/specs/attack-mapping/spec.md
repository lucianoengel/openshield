## ADDED Requirements

### Requirement: Detection signals map to MITRE ATT&CK techniques

The system SHALL map the detection signals it produces — credential detector types, threat-intel
categories, the exfil channel, and behavioral findings — to the MITRE ATT&CK technique ids they evidence,
returning a deduplicated set carrying only technique id and name (no matched content). A signal set with
no mappable signal MUST yield no techniques.

#### Scenario: A credential detection evidences unsecured-credentials

- **WHEN** a credential detector type is present
- **THEN** the mapping includes the unsecured-credentials technique

#### Scenario: A known-bad destination evidences command-and-control

- **WHEN** a threat-intel domain/IP/URI match is present
- **THEN** the mapping includes the application-layer-protocol (C2) technique

#### Scenario: Cloud-sync exfil and a LOLBin evidence their techniques

- **WHEN** the exfil channel is cloud-sync and a LOLBin behavioral flag is set
- **THEN** the mapping includes the cloud-storage-exfiltration technique and the system-binary-proxy
  technique

#### Scenario: No signals yield no techniques

- **WHEN** no mappable signal is present
- **THEN** the mapping is empty

### Requirement: Techniques are exposed to policy

The system SHALL expose the mapped techniques to the policy as a content-free derivation of the state, so
a policy can route on a technique and downstream reporting/correlation can group by it.

#### Scenario: A policy sees the techniques of a detection

- **WHEN** a state carries mappable signals
- **THEN** the policy input includes the corresponding technique ids
