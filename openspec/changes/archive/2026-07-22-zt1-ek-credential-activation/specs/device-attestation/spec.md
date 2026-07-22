## ADDED Requirements

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
