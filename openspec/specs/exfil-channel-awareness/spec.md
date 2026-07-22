# exfil-channel-awareness Specification

## Purpose
Classify which exfiltration channel a file event is on — removable media, a cloud-sync folder, or
local — so a policy can act on the channel, not only the content: sensitive data landing in a synced
cloud folder or on a removable drive is exfiltration; the same content in a temp dir is not. The
channel is a pure, content-free derivation of the path (no file access, no blocking mount lookup in
the decision path). This covers the file-based channels; the non-file producers (clipboard, print,
screenshot) and content-aware CASB are per-OS/integration follow-ups.


### Requirement: Exfil-channel classification of a file path

The system SHALL classify the exfiltration channel a file path is on — removable media (under a
configured mount root), a cloud-sync folder (identified by a folder-name component), or local as the
explicit default — from the path alone, without opening the file or performing a blocking filesystem
lookup in the decision path. Every classified path MUST yield a concrete channel, never an absent value.

#### Scenario: A removable-media path is classified

- **WHEN** a file path is under a configured removable mount root
- **THEN** it is classified as removable media

#### Scenario: A cloud-sync folder path is classified

- **WHEN** a file path contains a configured cloud-sync folder-name component
- **THEN** it is classified as cloud-sync, regardless of the home/prefix

#### Scenario: An ordinary path is local

- **WHEN** a file path matches no removable root and no cloud-sync folder
- **THEN** it is classified as local

### Requirement: Policy sees the exfil channel of a file event

The system SHALL expose the exfil channel of a filesystem event to the policy so a rule can escalate a
sensitive write to an exfiltration channel differently from a local write. The channel MUST be a
content-free derivation of the event's path.

#### Scenario: A policy escalates a sensitive write to an exfil channel

- **WHEN** a policy that escalates on sensitive content plus a non-local exfil channel evaluates a
  sensitive file written to a cloud-sync or removable path
- **THEN** the decision escalates, while the same sensitive content written to a local path does not
