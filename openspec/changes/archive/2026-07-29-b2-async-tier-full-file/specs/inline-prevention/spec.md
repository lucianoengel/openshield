# inline-prevention

## ADDED Requirements

### Requirement: A gated open MUST be fully classified after it is decided

The engine MUST submit a gated file-open event to the asynchronous tier after answering it, so the
whole file is classified, recorded and contained by the normal pipeline rather than only the bounded
prefix the inline decision used.

The inline decision is friction by design (D16) — it sees only a prefix, so content past that ceiling
is invisible to it. Without the second tier that content is neither refused inline nor detected
afterwards.

#### Scenario: A gated open produces a full classification

- **WHEN** a file open is decided by the gate
- **THEN** the whole file MUST subsequently be classified by the asynchronous pipeline

#### Scenario: Content past the inline prefix is still detected

- **WHEN** a file carries a detectable value beyond the inline prefix ceiling
- **THEN** the asynchronous classification MUST detect it even though the inline decision did not

### Requirement: Asynchronous submission MUST NOT recurse

Submitting a gated open for asynchronous classification MUST NOT cause further asynchronous
submissions for the same file, and the resulting sequence of gate decisions MUST terminate.

The asynchronous classification opens the file, and that open is itself subject to the gate. Without a
break, answering it would submit again without end — and because the opener is blocked in an
uninterruptible permission window, the failure is a hung host rather than a failing test.

#### Scenario: The classification's own open does not resubmit

- **WHEN** the asynchronous classification opens the file it was asked to classify
- **THEN** that open MUST receive a verdict
- **AND** MUST NOT produce a further asynchronous submission

#### Scenario: Repeated opens still receive verdicts

- **WHEN** the same file is opened again while its asynchronous submission is still suppressed
- **THEN** the open MUST still receive a verdict

### Requirement: Gate verdicts MUST have reserved classification capacity

The engine MUST reserve classification capacity for gate verdicts, separate from the capacity used by
asynchronous classification.

A nested gate decision is triggered by the very asynchronous work that would otherwise consume the
last worker. Sharing capacity means the gate fails open precisely when it is busiest, which is
indistinguishable from a gate that is working.

#### Scenario: Asynchronous load does not starve gate verdicts

- **WHEN** asynchronous classification is consuming its capacity
- **THEN** a gate verdict MUST still be answered from reserved capacity
