## ADDED Requirements

### Requirement: Automated network enrollment via credential activation

The system SHALL enroll a device over the network only after the device proves its AK is resident in a
genuine TPM by credential activation: the device submits its EK, AK, and PCR state; the gateway issues a
credential-activation challenge bound to the device's EK and AK name; and the gateway enrolls the device
only when the device returns the secret recovered by activating that challenge with its TPM. A device
that cannot recover the challenge secret MUST NOT be enrolled, and no enrollment MUST occur without a
verified activation.

#### Scenario: A genuine device enrolls over the wire and can then attest

- **WHEN** a device runs the enrollment handshake and activates the gateway's challenge with its TPM
- **THEN** the gateway enrolls it, and the device can subsequently attest and be marked attested

#### Scenario: A device that cannot activate the challenge is refused

- **WHEN** the device presented cannot recover the challenge secret (its EK cannot decrypt it, or its AK
  name does not match)
- **THEN** the gateway refuses the enrollment and the device is not enrolled
