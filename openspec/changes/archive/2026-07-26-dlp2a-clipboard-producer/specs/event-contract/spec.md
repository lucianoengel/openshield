## ADDED Requirements

### Requirement: The event contract expresses a clipboard copy, content-free

The event contract SHALL include a clipboard-copy event kind and a clipboard subject shape carrying only
the copied byte count and the display server it came from. The clipboard subject SHALL NOT contain any
field capable of carrying the copied content — no bytes field, no text field — so a clipboard event cannot
express content even by mistake (D10/D29).

The existing guard that every bytes field in the Event tree is explicitly allowlisted SHALL continue to
pass WITHOUT adding an entry, which is the mechanical proof that this addition carries no content.

#### Scenario: The clipboard subject cannot carry content
- **WHEN** the Event message tree is walked for bytes fields
- **THEN** the clipboard subject contributes none, and the allowlist is unchanged

#### Scenario: A clipboard event is distinguishable by kind
- **WHEN** a clipboard event is produced
- **THEN** its kind identifies it as a clipboard copy, so a policy and a correlation rule can select it
