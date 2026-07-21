## ADDED Requirements

### Requirement: A Decision is recorded before enforcement, and enforcement is audited
The engine MUST record a Decision before attempting enforcement, and MUST audit the enforcement
outcome — a failed enforcement is a high-severity audit event, never silence. With no enforcers
registered the engine MUST NOT enforce (observe-only default).

The audit must show what was decided even if enforcement fails or the machine dies mid-enforce, so
recording precedes enforcing. A silent enforcement failure is the quiet failure D14 forbids. And D1
keeps observe-only the default — enforcement is opt-in, per action.

#### Scenario: No enforcers means observe-only
- **WHEN** the engine processes an event with no enforcers registered
- **THEN** it records the Decision and enforces nothing
- **AND** a test asserts no enforcement occurred

#### Scenario: A matching enforcer carries out the Decision, audited
- **WHEN** a Decision with an enforceable action is produced and a registered enforcer advertises it
- **THEN** the Decision is recorded, the enforcer is invoked, and the enforcement outcome is audited
- **AND** a test asserts the order (recorded before enforced) and that both are in the ledger

#### Scenario: Enforcement failure is high-severity and audited
- **WHEN** an enforcer returns an error
- **THEN** a high-severity audit entry records the enforcement failure
- **AND** a test asserts the failure is recorded, not swallowed

### Requirement: Post-decision enforcement contains, it does not prevent
Documentation and any surface MUST describe enforcement as CONTAINMENT after detection (quarantine,
encrypt, revoke), not PREVENTION of the access that triggered it. Inline blocking within the
permission window is not provided.

The file was already read — that is how it was classified. Post-decision enforcement moves,
encrypts or revokes after the fact; it does not stop the open. Calling this "prevention" would be
the exact overclaim the threat model forbids (D16); inline blocking stays deferred because the
pipeline cannot complete in the permission window (T-002).

#### Scenario: No surface claims prevention
- **WHEN** enforcement is described
- **THEN** it is described as post-decision containment, defeatable by root, with inline blocking
  named as deferred and infeasible for classification-dependent decisions
