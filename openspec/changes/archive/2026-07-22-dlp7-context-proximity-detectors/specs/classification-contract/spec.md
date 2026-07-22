## ADDED Requirements

### Requirement: Context-proximity detection of weak-format identifiers

The system SHALL detect an identifier whose format is too weak to fire on its own (a passport number, a
driver's license) only when the value pattern appears within a proximity window of a context keyword, so
a bare value far from any keyword does not fire. Such a detection MUST report a distinct detector type
and carry only type, confidence, and count — never the matched value.

#### Scenario: A value near its context keyword is detected

- **WHEN** a passport or driver's license value appears within the proximity window of its context
  keyword
- **THEN** the detector reports a hit of the corresponding detector type

#### Scenario: The same value with no nearby keyword is not detected

- **WHEN** the same value appears with no context keyword within the window
- **THEN** the detector reports no hit

#### Scenario: A context keyword with no value nearby is not detected

- **WHEN** a context keyword appears but no matching value is within the window
- **THEN** the detector reports no hit
