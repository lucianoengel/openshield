# audit-ledger delta

## ADDED Requirements

### Requirement: External anchoring is runnable and schedulable
The system MUST provide a runnable path that witnesses the ledger head with a persistent, externally
held witness key and stores the anchor, so a deployment can move off permanent `Completeness:
UNVERIFIED` — the anchoring mechanism (T-019/D38) must actually run, not exist only as a library call.

The witness process MUST hold only the witness key, never the ledger signer (it attests, it cannot
append). A witness key MUST be persistable and reloadable, so anchors are witnessed under a stable key
a verifier can check. Witness custody determines the guarantee (a key the deployer controls attests to
little), and the undetectable-loss window is the interval between anchors.

#### Scenario: Anchoring moves completeness off UNVERIFIED
- **WHEN** a witness reconstructed from a saved key anchors the current head and verification is run
  with that witness's public key
- **THEN** verification reports the range as anchored, not UNVERIFIED
- **AND** a test asserts the completeness transition, and the witness process opens the ledger without
  the ledger signer

#### Scenario: An auditor verifies completeness against the witness public key
- **WHEN** an auditor runs verification supplying the witness public key
- **THEN** the anchored range is reported; without the witness key, the honest UNVERIFIED degraded
  mode is reported unchanged
- **AND** the verification surface remains signer-less (it cannot produce entries or anchors)
