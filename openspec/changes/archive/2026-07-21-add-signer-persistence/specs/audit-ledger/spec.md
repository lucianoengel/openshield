## ADDED Requirements

### Requirement: The ledger signer resumes its chain across a restart
The signer's CURRENT state MUST be exportable and reloadable such that a new process reconstructs an
identical signer and continues the SAME chain — the reloaded signer's anchor matches the stored
chain, so writing resumes rather than forking or being refused. Only the current epoch's private key
is persisted; destroyed keys MUST NOT be.

An append-only evidentiary log that cannot continue after a reboot is a real hole. The public chain
is persisted already; the missing piece is the current private key. Persisting only the current
epoch keeps forward security intact — that epoch is already the compromise window, and earlier keys
were destroyed and are absent.

#### Scenario: A reloaded signer continues the chain
- **WHEN** entries are appended, the signer is exported, a fresh process loads it, reopens the
  ledger, and appends more
- **THEN** the reopen succeeds (the anchor matches) and the full chain verifies continuously
- **AND** a test drives export→reload→resume and asserts one continuous verifiable chain

#### Scenario: A corrupt or mismatched export fails to load
- **WHEN** a signer blob is corrupted, or its private key does not match the chain's current epoch
- **THEN** loading returns an error rather than a signer that signs under a key the chain omits

#### Scenario: Destroyed keys are not in the export
- **WHEN** an exported signer that has evolved is inspected
- **THEN** it contains only the current epoch's private key, not any prior epoch's
