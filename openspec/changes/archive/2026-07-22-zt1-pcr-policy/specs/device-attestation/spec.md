## ADDED Requirements

### Requirement: PCR baseline capture and expected-digest computation

The system SHALL read a TPM's current PCR values so an operator can capture a known-good baseline, and
SHALL compute the expected aggregate PCR digest from a set of PCR values the same way a TPM does — the
hash over the selected PCR values in ascending index order — so a server holding no TPM can compare it
to a quote's attested digest.

#### Scenario: Expected digest matches the TPM's quoted digest for the same state

- **WHEN** the server computes the expected aggregate digest from PCR values captured from a machine and
  that machine quotes the same PCRs
- **THEN** the computed digest equals the quote's attested PCR digest

### Requirement: Measured-boot PCR policy evaluation

The system SHALL evaluate a verified quote against a golden PCR baseline, reporting the machine as
compliant only when the quote's attested PCR digest equals the digest of the golden baseline over the
quoted PCR selection, and MUST reject any drift from that baseline with a distinct error. A policy with
no baseline MUST be an error, never an implicit allow.

#### Scenario: Golden state is compliant

- **WHEN** a policy built from a machine's golden PCR values evaluates a verified quote taken while the
  machine is in that state
- **THEN** the policy reports compliant

#### Scenario: Drifted state is rejected

- **WHEN** the machine's PCR state changes after the baseline was captured and it produces a new verified
  quote
- **THEN** the same policy rejects it with a PCR-mismatch error
