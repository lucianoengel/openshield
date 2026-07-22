## ADDED Requirements

### Requirement: Attestation enrollment distribution

The system SHALL capture a device's attestation trust anchors — its subject, AK public key, and golden
PCR baseline — into a distributable record, and SHALL load such records into the gateway's attestation
verifier so a distributed device can attest exactly as a programmatically-enrolled one does. A malformed
or incomplete enrollment record MUST fail the load with an error, never be silently skipped.

#### Scenario: A distributed enrollment lets a device attest end to end

- **WHEN** a device's enrollment record is captured, written to the enrollment file, and loaded into the
  gateway verifier, and that device then attests over the channel
- **THEN** the gateway marks the device attested, identically to a programmatic enrollment

#### Scenario: A malformed enrollment record fails the load

- **WHEN** an enrollment record has no subject, an unparseable AK public key, or an empty PCR baseline
- **THEN** loading the enrollment file returns an error and does not partially enroll
