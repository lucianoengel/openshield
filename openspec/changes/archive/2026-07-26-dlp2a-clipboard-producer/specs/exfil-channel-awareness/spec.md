## ADDED Requirements

### Requirement: The clipboard is a first-class exfiltration channel

The exfil channel model SHALL include a clipboard channel alongside local, removable media and cloud sync,
and a clipboard event SHALL be tagged with it when policy input is built. A channel-aware policy SHALL
therefore be able to treat a sensitive copy-paste the same way it treats a sensitive write to a cloud-sync
folder, without knowing anything clipboard-specific.

Unlike the other channels, this one is NOT derived from a filesystem path — a clipboard copy has no path —
so it SHALL be assigned from the event kind rather than by path classification.

#### Scenario: A clipboard event reaches policy tagged as the clipboard channel
- **WHEN** policy input is built for a clipboard-copy event
- **THEN** its exfil channel is the clipboard channel
- **AND** a path-derived channel is not inferred for it
