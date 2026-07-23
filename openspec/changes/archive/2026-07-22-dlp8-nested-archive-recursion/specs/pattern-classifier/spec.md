## ADDED Requirements

### Requirement: Content inside archives is extracted and classified

The classifier SHALL extract and classify the content of files inside a ZIP archive, including a file
inside a nested archive (a zip within a zip), so a sensitive value placed in an archive is detected
rather than scanned as opaque compressed bytes. Extraction SHALL be bounded against a decompression
bomb by a total-size budget shared across the whole recursion and a maximum nesting depth; beyond the
bounds the remaining bytes are scanned as-is rather than expanded.

#### Scenario: A sensitive file in a plain zip is detected
- **WHEN** a sensitive value (e.g. a valid card number) is placed in a plain-text file inside a ZIP and classified
- **THEN** the corresponding detector reports a hit

#### Scenario: A double-zipped sensitive file is detected
- **WHEN** the sensitive file is inside a ZIP that is itself inside another ZIP
- **THEN** the detector still reports a hit

#### Scenario: A non-archive is scanned as-is
- **WHEN** the input is plain text (not an archive)
- **THEN** it is scanned directly and detection is unchanged

#### Scenario: A decompression bomb is bounded
- **WHEN** a deeply nested or oversized archive is classified
- **THEN** extraction stops at the size/depth bounds without exhausting memory
