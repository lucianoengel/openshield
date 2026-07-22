# device-attestation Specification

## Purpose
The hardware-root-of-trust primitive OpenShield posture attestation is built on. Device posture is
otherwise self-reported: the agent signs a set of booleans with its software key, which proves which
agent spoke but not that the claim is true — a compromised-but-alive agent signs `Compliant=true`.
This capability lets an agent produce a TPM-signed quote over the machine's measured-boot PCR state,
bound to a server-issued nonce, and lets a server verify that quote against the attesting key without
holding a TPM of its own. It is the crypto core: binding the attesting key to a genuine TPM (via the
Endorsement Key), turning PCR values into a measured-boot policy verdict, and feeding an `attested`
posture signal are later increments — until the Endorsement-Key binding lands, a verifier trusts an
attesting key by its raw public key only.

## Requirements

### Requirement: TPM Attestation Key generation

The system SHALL create a restricted signing Attestation Key (AK) inside a TPM 2.0 device and export
the AK's public half in a form a server can persist, so that later quotes signed by that AK can be
verified without further TPM access. The AK's private half MUST be non-exportable (`FixedTPM`,
`SensitiveDataOrigin`) and restricted to signing TPM-internal structures.

#### Scenario: AK is created and its public key is usable off-device

- **WHEN** the agent creates an AK against a TPM and marshals the returned public key
- **THEN** the marshaled public key round-trips back to an equivalent verification key that a server
  holding no TPM can load and use to verify a quote

#### Scenario: AK private key never leaves the TPM

- **WHEN** an AK is created
- **THEN** the key template requests a fixed, TPM-resident, restricted signing key and no private-key
  material is present in the exported public structure

### Requirement: Nonce-bound TPM quote generation

The system SHALL produce a TPM quote over a caller-selected set of PCRs, binding a caller-supplied
nonce into the quote as its qualifying data, so that a verifier can prove both the PCR state and the
freshness of the attestation. The quote MUST be signed by the AK.

#### Scenario: Quote carries the requested nonce and PCR selection

- **WHEN** the agent quotes PCRs [0,7] with a fresh nonce using the AK
- **THEN** the returned attestation blob is a genuine quote structure whose qualifying data equals the
  supplied nonce and whose PCR selection matches the request

### Requirement: Server-side quote verification with anti-replay

The system SHALL verify a TPM quote server-side against a stored AK public key, and MUST reject the
quote unless (a) the signature is valid under that AK public key, (b) the blob is a genuine quote
structure with the TPM-generated magic value, and (c) the quote's qualifying data equals the exact
nonce the verifier issued for this attestation. On success it SHALL expose the attested PCR digest for
a later policy layer to evaluate.

#### Scenario: Fresh valid quote verifies

- **WHEN** a verifier checks a quote taken over the same nonce it issued, against the correct AK public
  key
- **THEN** verification succeeds and returns the attested PCR digest

#### Scenario: Replayed quote is rejected (nonce mismatch)

- **WHEN** a verifier checks a quote whose qualifying data is an old nonce against a different expected
  nonce
- **THEN** verification fails and no attested state is returned

#### Scenario: Tampered signature is rejected

- **WHEN** a verifier checks a quote whose signature bytes have been altered
- **THEN** verification fails

#### Scenario: Quote bound to a different AK is rejected

- **WHEN** a verifier checks a valid quote against the public key of a different AK than the one that
  signed it
- **THEN** verification fails

### Requirement: TPM Endorsement Key exposure

The system SHALL create an Endorsement Key (EK) in the TPM's endorsement hierarchy and expose its
public key, so a verifier can address a credential-activation challenge to that specific TPM. The EK
MUST be a decryption key distinct from the signing Attestation Key.

#### Scenario: EK public key is available for enrollment

- **WHEN** the endpoint creates an EK
- **THEN** its public key is exported in a form the server can load to build a credential challenge

### Requirement: Server-side credential challenge without a TPM

The system SHALL let a server that holds no TPM construct a credential-activation challenge that
encrypts a fresh random secret to a given EK public key, bound to a given AK name. The challenge MUST be
usable only by the TPM holding that EK's private key together with the named AK.

#### Scenario: Challenge is built from EK public and AK name

- **WHEN** the server builds a challenge for an enrolled EK public key and AK name
- **THEN** it produces a credential blob and encrypted secret, and retains the expected secret for
  verification

### Requirement: AK proven resident in a genuine TPM via credential activation

The system SHALL bind an AK to a TPM by credential activation: the endpoint's TPM recovers the
challenge secret with `TPM2_ActivateCredential`, and the server accepts the AK only when the recovered
secret equals the one it issued. The system MUST reject activation when the EK belongs to a different
TPM, and MUST reject a challenge whose bound AK name does not match the AK presented for activation.

#### Scenario: Same-TPM activation proves the binding

- **WHEN** the endpoint activates a challenge built for its own EK and AK
- **THEN** the recovered secret equals the issued secret and the AK is accepted as genuine-TPM-resident

#### Scenario: A different TPM's EK cannot activate

- **WHEN** a challenge built for one TPM's EK is presented to a different TPM
- **THEN** activation does not recover the issued secret and the AK is rejected

#### Scenario: A substituted AK breaks the name binding

- **WHEN** a challenge built for one AK's name is activated against a different AK
- **THEN** activation fails and the AK is rejected

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

### Requirement: Attestation challenge and report transport

The system SHALL carry a device attestation exchange over the messaging channel: a device requests a
fresh nonce for its subject and receives it, then publishes a report containing its quote over that
nonce, and the gateway verifies each received report through the attestation verifier. A report that
fails verification MUST be dropped and counted, never silently accepted, and the transport MUST NOT add a
second authentication layer over the quote — the quote authenticates itself against the enrolled AK.

#### Scenario: A device attests over the live channel

- **WHEN** an enrolled device requests a challenge, quotes over the returned nonce, and publishes the
  report
- **THEN** the gateway verifies the report and marks the device attested

#### Scenario: A forged or stale report on the channel is rejected

- **WHEN** a report with a mismatched nonce or a quote not signed by the enrolled AK is published
- **THEN** the gateway rejects it, counts it, and does not mark the device attested

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

### Requirement: Continuous re-attestation from the endpoint

The system SHALL let an endpoint re-attest on an interval so the gateway's attested signal tracks the
device's current state: after a device's measured state drifts from its enrolled baseline, a subsequent
re-attestation MUST be rejected by the gateway and the device MUST lose its attested status. A
re-attestation failure MUST NOT be fatal to the endpoint.

#### Scenario: A good device stays attested across cycles

- **WHEN** an enrolled device runs the re-attestation loop in its golden state
- **THEN** the gateway keeps it attested across successive cycles

#### Scenario: A drifted device loses attestation within a cycle

- **WHEN** an enrolled device's PCR state drifts after enrollment while the loop is running
- **THEN** the gateway rejects the next re-attestation and the device is no longer attested
