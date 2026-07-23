## ADDED Requirements

### Requirement: Network enrollment anchors the EK to a manufacturer-certified TPM

The system SHALL, when configured with a pool of manufacturer root certificates, refuse a network
enrollment whose Endorsement Key is not certified by that pool. The device SHALL submit an EK certificate;
the system SHALL verify that certificate chains to a configured manufacturer root AND that the
certificate's public key equals the submitted EK public key, refusing the enrollment before issuing a
credential-activation challenge if either check fails. Without a configured roots pool the system SHALL
preserve the prior (unanchored) behavior and SHALL surface that the anchor is disabled.

#### Scenario: An uncertified EK is refused
- **WHEN** a device requests enrollment with no EK certificate, or one that does not chain to a configured
  manufacturer root, and the anchor is enabled
- **THEN** the enrollment is refused before any challenge is issued and no pending state is stored

#### Scenario: A manufacturer-certified EK is challenged
- **WHEN** a device requests enrollment with an EK certificate that chains to a configured manufacturer
  root and whose public key equals the submitted EK public key
- **THEN** the enrollment proceeds to the credential-activation challenge

#### Scenario: A vendor certificate for a different EK is refused
- **WHEN** a device submits a genuine manufacturer-chained EK certificate whose public key does NOT equal
  the submitted EK public key
- **THEN** the enrollment is refused (the certificate must be bound to the EK being challenged)
