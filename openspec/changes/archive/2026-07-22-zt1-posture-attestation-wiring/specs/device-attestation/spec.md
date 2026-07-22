## ADDED Requirements

### Requirement: Device attestation report verification sets the attested signal

The system SHALL verify a device attestation report server-side and derive the device's attested state
from that verification alone — never from a value the device asserts. Verification MUST require, in
order: the report's nonce equals a fresh nonce the verifier issued for that device and has not already
consumed; the quote verifies against the device's enrolled AK public key; and the quote's PCR state
satisfies the device's golden baseline. A device with no enrollment MUST NOT be attestable.

#### Scenario: A valid report over a fresh nonce marks the device attested

- **WHEN** an enrolled device answers a challenge with a quote over the issued nonce, in its golden PCR
  state
- **THEN** the verifier marks that device attested

#### Scenario: A replayed report is rejected

- **WHEN** a report that already succeeded is submitted again under the same nonce
- **THEN** verification fails and the device is not (re-)marked attested from it

#### Scenario: A drifted device is not attested

- **WHEN** an enrolled device answers a challenge but its PCR state has drifted from its golden baseline
- **THEN** verification fails and the device is not attested

#### Scenario: A report from an unenrolled device is rejected

- **WHEN** a report names a device the verifier has no enrollment for
- **THEN** verification fails

### Requirement: Device posture carries a server-verified attested signal

Device posture SHALL carry an `Attested` signal that is set only by the gateway's own verification of a
device attestation report, and the Zero-Trust access policy SHALL be able to require it. Absent or
unverified attestation MUST leave the device unattested (fail closed), and the attested state MUST NOT be
settable by the endpoint's self-reported posture.

#### Scenario: A policy can require a hardware-attested device

- **WHEN** an access policy requires `device_posture.attested` and the connecting device has been verified
  attested by the gateway
- **THEN** the policy admits it, and denies an otherwise-identical device that has not been verified
