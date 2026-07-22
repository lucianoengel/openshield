## ADDED Requirements

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
