## ADDED Requirements

### Requirement: India Aadhaar detection

The classifier SHALL detect an India Aadhaar number by validating its Verhoeff checksum and first-digit
constraint, reporting a checksum-tier confidence. A 12-digit candidate that fails the checksum SHALL NOT
be counted.

#### Scenario: A valid Aadhaar is detected
- **WHEN** content contains a Verhoeff-valid 12-digit Aadhaar (spaced or bare)
- **THEN** the Aadhaar detector reports a hit

#### Scenario: A checksum-invalid candidate is not counted
- **WHEN** a 12-digit number whose Verhoeff check digit is wrong appears
- **THEN** the Aadhaar detector does not count it

### Requirement: UK National Insurance Number detection

The classifier SHALL detect a UK NINO of the official format only when a National-Insurance context
keyword appears within the proximity window, reporting a context-tier confidence — reusing the
keyword-proximity primitive (no checksum exists for NINO).

#### Scenario: A NINO near its keyword is detected
- **WHEN** a well-formed NINO appears near a "national insurance"/"NINO" keyword
- **THEN** the NINO detector reports a hit

#### Scenario: A bare NINO with no context is not fired
- **WHEN** a NINO-shaped value appears with no nearby National-Insurance keyword
- **THEN** the NINO detector does not count it
