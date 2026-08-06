# device-attestation

## ADDED Requirements

### Requirement: The endpoint that runs the pipeline can attest to its hardware

The binary that observes, classifies and enforces SHALL be able to attest continuously against a TPM. A
simulator attesting SHALL NOT be treated as satisfying this.

The verifier fails closed, so with no real producer a policy requiring attestation refused every genuine
endpoint while admitting simulated ones.

#### Scenario: A verified quote admits a device an attestation-requiring policy had refused
- **WHEN** a policy requiring attestation denies a device that has published no quote
- **AND** that device's endpoint agent then attests with a real TPM
- **THEN** the same request from the same identity is admitted

#### Scenario: Attestation does not stop the endpoint doing its work
- **WHEN** an endpoint is configured to attest
- **THEN** it continues observing, so a TPM that never answers costs only attestation

### Requirement: The agent-side attestation orchestration is shared, not duplicated per binary

The sequence that opens the TPM, creates the attestation key, optionally self-enrols and re-attests SHALL
exist once and be used by every agent that attests.

Two binaries with their own copy of this sequence will come to disagree about what "attested" means, and
the disagreement will be discovered by whichever one a deployment happens to run.

#### Scenario: Both agents attest through the same path
- **WHEN** either the endpoint agent or the fleet simulator attests
- **THEN** it runs the same orchestration
