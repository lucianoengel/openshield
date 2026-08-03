# attack-mapping Specification

## Purpose
Map OpenShield's detection signals — credential detector types, threat-intel categories, the exfil
channel, and behavioral findings — to MITRE ATT&CK technique ids, so detections carry a shared
adversary vocabulary. The mapping is centralized (one curated table) and content-free (a technique id
+ name, no matched content). SIEM reporting groups by technique and the XDR correlation lane reuses the
same mapping as its sequence vocabulary. A curated starter set over today's signals — not the full matrix.

## Requirements

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

### Requirement: The ATT&CK technique vocabulary is closed and derivable-only

The set of technique ids the system may emit SHALL be a single closed vocabulary, and every id the
signal mapper can produce SHALL be a member of it. The system SHALL expose that membership check so a
consumer can refuse an id from outside the vocabulary.

An id in the vocabulary that no signal shape can produce SHALL be reported as a defect: it would be
accepted in an operator's hunt and could never match.

Sub-technique ids SHALL NOT be rolled up to their parents. When the mapper derives `T1567.002`, the
system SHALL NOT also emit `T1567` — the parent is a broader claim than the evidence supports.

#### Scenario: Every derivable technique is a vocabulary member
- **WHEN** every signal shape the mapper branches on is evaluated
- **THEN** each technique id produced is a member of the vocabulary, and each has a display name

#### Scenario: An id outside the vocabulary is not recognized
- **WHEN** the membership check is asked about an invented id, a real ATT&CK id this build cannot
  derive, a differently-cased id, or the parent of a derived sub-technique
- **THEN** it reports the id as unknown

### Requirement: A technique id is stable; its name is looked up per build

A technique's ID SHALL be the value that crosses a contract boundary or is persisted. The display NAME
SHALL be resolved at presentation time from the running build's table, and SHALL NOT be persisted
alongside the id.

MITRE renames techniques, and a name written into a hash-chained ledger is frozen at the moment of
writing and cannot be corrected without breaking the chain.

#### Scenario: A name is resolved, not stored
- **WHEN** a technique id is carried on a decision or an alert
- **THEN** only the id is stored, and the display name is obtained by looking the id up
