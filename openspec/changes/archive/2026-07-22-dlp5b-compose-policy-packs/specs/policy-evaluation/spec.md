## MODIFIED Requirements

### Requirement: Ready-made compliance policy packs are selectable
The policy layer MUST provide ready-made compliance packs (at least PCI, HIPAA, and GDPR) as
selectable policies, each alerting when a detector in that regulation's scope is present and allowing
otherwise, observe-only (alert, not block). Selecting a pack MUST COMPOSE it WITH the default policy,
never replace the default — so the default's protections (behavioral process alerting and the
strong-detector alert) remain in force while a pack is enabled. Selecting an unknown pack MUST be an
error, never a silent fallback to a permissive policy, and the identity of the composed bundle
(the default plus each selected pack) MUST be stamped on the resulting decision.

#### Scenario: A pack alerts on its scope and an unknown pack is refused
- **WHEN** a compliance pack evaluates data in its regulatory scope, data outside its scope, and a binary is configured with an unknown pack name
- **THEN** the in-scope data alerts, the out-of-scope data is allowed by that pack, and the unknown pack name is refused rather than silently applying a permissive policy

#### Scenario: The default's protections survive pack selection
- **WHEN** a pack is enabled and an input matches a default protection outside that pack's scope — a suspicious process-behavior score, and separately a checksum-backed CPF
- **THEN** each still ALERTs (the behavioral alert and the strong-detector alert are not lost), because the pack composes with the default rather than replacing it

## ADDED Requirements

### Requirement: Composed policies combine under a most-restrictive-wins data-verb lattice

The policy layer MUST, when more than one module is active (the default plus one or more packs and an
optional operator custom module), evaluate each module independently over the same input and combine
their decisions under a total, most-restrictive-wins ordering of the data-plane verbs:
`ALLOW < ALERT < REDIRECT < ENCRYPT_LOCAL < QUARANTINE_LOCAL < BLOCK` (QUARANTINE_LOCAL outranks
ENCRYPT_LOCAL). The composed decision MUST be the highest-ranked candidate, carrying that candidate's
reason and confidence. The process-control verbs `DENY_EXEC` and `KILL_PROCESS` MUST NOT be part of
this lattice, and a COMPLIANCE PACK that yields a process-control verb MUST be rejected as an error —
a pack MUST NOT be able to escalate to killing or denying a process. The composition MUST NOT weaken
determinism: identical input MUST still yield an identical composed decision.

#### Scenario: The most-restrictive verb across modules wins
- **WHEN** two active modules decide different data-plane verbs for the same input (for example one ALLOW and one BLOCK, or one ALERT and one QUARANTINE_LOCAL)
- **THEN** the composed decision is the more-restrictive verb (BLOCK over ALLOW; QUARANTINE_LOCAL over ALERT), with that module's reason

#### Scenario: A compliance pack cannot escalate to a process-control verb
- **WHEN** a compliance pack is composed whose decision yields `KILL_PROCESS` (or `DENY_EXEC`)
- **THEN** composition fails with an error rather than allowing the pack's process-control verb to take effect

#### Scenario: A single policy behaves exactly as before
- **WHEN** only one module is active (just the default, or a single explicitly-built policy)
- **THEN** the composed decision equals that module's decision unchanged — composition of one member is the identity
