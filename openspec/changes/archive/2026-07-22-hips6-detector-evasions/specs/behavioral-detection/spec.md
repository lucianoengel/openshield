# behavioral-detection (delta)

## ADDED Requirements

### Requirement: The behavioral detector resists near-miss command evasions
The behavioral detector MUST recognize an encoded-command flag by the tool's own prefix semantics
(any unambiguous prefix of the encoded-command parameter), not a fixed literal list, and MUST
recognize a downloader piped into ANY common shell, not only sh/bash. It MUST NOT trip on an
innocent short flag that is not a prefix of the encoded-command parameter.

#### Scenario: Prefix and non-bash-shell evasions are detected, innocent flags are not
- **WHEN** the detector analyzes an encoded-command prefix (e.g. -encod), a downloader piped into a non-bash shell (e.g. curl x | zsh), and an innocent flag (e.g. -export)
- **THEN** the encoded-command and cradle evasions are detected while the innocent flag does not trip the detector
