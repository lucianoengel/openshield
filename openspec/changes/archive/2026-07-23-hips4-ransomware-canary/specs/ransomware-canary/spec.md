## ADDED Requirements

### Requirement: A ransomware canary fires on correlated mass change of decoys

The system SHALL plant decoy (canary) files in operator-designated directories and record their known-good
baseline, and SHALL fire a ransomware detection when the number of DISTINCT canaries whose content changed
(or that were deleted) within a configured time window reaches a configured threshold. A change to a single
canary MUST NOT fire the detection (a lone anomaly), and changes spread across a period longer than the
window MUST NOT accumulate to a false detection (old changes prune out of the window). A change MUST be
confirmed by a content-hash difference, not a raw filesystem event, so a metadata touch that does not
change content is not counted.

#### Scenario: A burst of canary changes fires
- **WHEN** the threshold number of distinct canaries change within the window
- **THEN** a ransomware detection is fired

#### Scenario: A single canary change does not fire
- **WHEN** only one canary changes
- **THEN** no ransomware detection is fired

#### Scenario: Slow, spread-out changes do not accumulate
- **WHEN** canary changes occur but are spread over a period longer than the window
- **THEN** no ransomware detection is fired (changes older than the window are pruned)

### Requirement: A ransomware detection enters the pipeline as a high-severity event

The system SHALL emit a detected ransomware attack as a distinct high-severity event carrying the affected
location (a directory path) but no file content, so a policy can decide (for example, alert). The event
MUST reach the policy on its metadata — it MUST NOT attempt to open the affected files, which may be
encrypted or deleted. Entropy of a changed canary's content MAY raise the event's confidence (a
high-entropy rewrite is the encryption signature), but a deleted or low-entropy-corrupted canary MUST
still count toward the detection.

#### Scenario: A ransomware detection becomes a policy alert
- **WHEN** the canary detector fires
- **THEN** a content-free ransomware event flows the pipeline to the policy, which can alert, and the outcome is audited without opening the affected files
