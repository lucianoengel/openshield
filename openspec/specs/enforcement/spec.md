# enforcement Specification

## Purpose
Post-decision enforcement: the engine records a Decision then dispatches it to a registered enforcer that carries it out, auditing the outcome (failure high-severity). Observe-only is the default; enforcement CONTAINS after detection (quarantine, encrypt, revoke), it does not PREVENT the triggering access; inline blocking is deferred (T-002 budget).
## Requirements
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

### Requirement: The encrypt-local action renders a flagged file unreadable in place
The engine MUST be able to dispatch `ENCRYPT_LOCAL` to an enforcer that replaces the flagged file's
contents with an authenticated ciphertext in place, so the file is genuinely unreadable without the
key — not merely relocated or renamed.

Encryption uses AES-256-GCM with a fresh per-file nonce, written atomically so a crash leaves either
the original or the fully-encrypted file. It is CONTAINMENT after detection, not prevention (the file
was already read to be classified), and its protection depends on key custody: an on-host key
defends against a stolen disk or a different user, not against the agent user or host root (D16).

#### Scenario: An encrypted file is unreadable without the key but recovers with it
- **WHEN** the encrypt-local enforcer encrypts a target file
- **THEN** the on-disk bytes differ from the plaintext and cannot be recovered with a wrong key
- **AND** a test decrypts with the correct key and recovers the exact original bytes

#### Scenario: Re-encrypting an already-encrypted file is idempotent
- **WHEN** the enforcer is applied to a file it has already encrypted
- **THEN** the file is not double-encrypted or corrupted and still recovers to the original plaintext
- **AND** a test asserts a second enforcement leaves the file recoverable

#### Scenario: No target is an error, never a silent no-op
- **WHEN** the enforcer is asked to encrypt with an empty target
- **THEN** it returns an error rather than reporting success
- **AND** a test asserts the empty-target error

### Requirement: A policy deciding encrypt-local routes to the enforcer and is audited
The engine MUST route an `ENCRYPT_LOCAL` Decision to a registered encrypt-local enforcer, encrypt the
target on disk, and audit the enforcement outcome, so enforcement is never silent (D14).

#### Scenario: Encrypt-local flows decision to encrypted file, audited
- **WHEN** a policy decides `ENCRYPT_LOCAL` for an event whose file is on disk and the encrypt-local
  enforcer is registered
- **THEN** the engine records the Decision, encrypts the file in place, and appends an enforcement
  outcome to the audit ledger
- **AND** an end-to-end test asserts the file is encrypted on disk and the outcome is recorded

### Requirement: Encrypt-local escrow mode seals so the endpoint cannot decrypt
The encrypt-local enforcer MUST support an escrow mode that seals a flagged file to a recipient PUBLIC
key such that the endpoint — holding only that public key — cannot decrypt it, so a fully-compromised
endpoint yields ciphertext it cannot open; recovery MUST require the recipient PRIVATE key held off
the endpoint.

Escrow uses Curve25519 anonymous sealed-box. Escrow blobs carry a distinct magic from symmetric
blobs so a blob is self-describing and recovery uses the right key. All D57 invariants hold: atomic
in-place replace, idempotent re-encryption, an empty target errors, and it is containment after
detection, not prevention. Escrow shifts trust to the private-key holder — it defends against
endpoint compromise, not against compromise of the escrow holder (whose key custody is D16).

#### Scenario: An escrow blob opens only with the private key
- **WHEN** the enforcer encrypts a file in escrow mode with a recipient public key
- **THEN** the on-disk blob cannot be decrypted with only the public key or the endpoint's material
- **AND** a test decrypts it with the recipient private key and recovers the exact original bytes, and
  a wrong private key fails

#### Scenario: Escrow and symmetric blobs do not cross
- **WHEN** a symmetric decrypt is attempted on an escrow blob (or vice versa)
- **THEN** it is rejected by the magic rather than silently mis-handled
- **AND** re-encrypting an already-encrypted file (either mode) is still an idempotent no-op

### Requirement: A policy deciding encrypt-local in escrow mode is audited
The engine MUST route an `ENCRYPT_LOCAL` Decision to a registered escrow-mode encrypt-local enforcer,
seal the target on disk so only the escrow private key recovers it, and audit the enforcement outcome
(never silent, D14).

#### Scenario: Escrow enforcement flows decision to sealed file, audited
- **WHEN** a policy decides `ENCRYPT_LOCAL` for an event whose file is on disk and an escrow-mode
  enforcer is registered
- **THEN** the engine records the Decision, seals the file to the recipient public key, and appends
  an enforcement outcome to the ledger
- **AND** an end-to-end test asserts the file recovers only with the escrow private key

### Requirement: File enforcers do not follow a symlink at the flagged path
A file enforcer MUST NOT read or act THROUGH a symlink at the target path, and MUST refuse a target
that is not a regular file — so an attacker who swaps the flagged path for a symlink (or a special
file) in the window between classification and enforcement cannot redirect enforcement onto an
arbitrary file.

The refusal is a loud, auditable enforcement failure (D14), never a silent redirect. This closes the
final-component symlink swap; a parent-directory-component swap and an fd carried from classification
remain documented follow-ups.

#### Scenario: A target swapped for a symlink is refused
- **WHEN** the target that was a regular file at classification is a SYMLINK at enforcement time
- **THEN** the enforcer refuses (errors) rather than reading or acting on the symlink's destination
- **AND** a test replaces the target with a symlink to a secret file and asserts the enforcer neither
  reads nor encrypts/quarantines the destination

#### Scenario: A non-regular target is refused; a regular file is handled
- **WHEN** the target is a directory, fifo, or device
- **THEN** the enforcer refuses it, while a genuine regular file is encrypted/quarantined as before
- **AND** a test asserts both outcomes


### Requirement: A flow enforcer resolves a flow_id target through a pluggable flow table
A flow enforcer MUST implement the existing `core.TargetedEnforcer`, advertise the network verdicts it
can carry out (BLOCK and REDIRECT), and resolve the `flow_id` enforce target to an action through a
`FlowTable` seam (`Block`/`Redirect` by flow id) rather than assuming a live socket. It MUST refuse to
act without a flow_id target, and MUST reject any action it does not advertise. This proves the
existing target-string enforcer interface generalises to a second domain (after files) with no change
to the enforcer interface.

#### Scenario: A BLOCK verdict is dispatched to the flow enforcer and reaches the flow table
- **WHEN** a BLOCK Decision is dispatched to a flow enforcer with a flow_id target
- **THEN** the enforcer invokes the flow table's block operation for that flow_id

#### Scenario: A REDIRECT verdict reaches the flow table's redirect operation
- **WHEN** a REDIRECT Decision is dispatched to a flow enforcer with a flow_id target
- **THEN** the enforcer invokes the flow table's redirect operation for that flow_id

#### Scenario: The flow enforcer refuses an action it does not advertise
- **WHEN** a Decision with an action outside {BLOCK, REDIRECT} reaches the flow enforcer
- **THEN** the enforcer returns an error rather than acting

### Requirement: The socket-backed flow table carries a verdict as a disposition the handler applies
The socket-backed flow table MUST record a per-flow disposition (allow, block, or redirect) when the
flow enforcer carries out a verdict, rather than acting on the socket itself, so the connection handler
that owns the flow applies the verdict without a race. A verdict for a flow that is not registered
(not live) MUST be an error, and the table MUST keep concurrent flows isolated.

#### Scenario: A BLOCK verdict sets the flow's disposition to block
- **WHEN** the flow enforcer carries out a BLOCK verdict for a registered flow_id
- **THEN** the flow table reports that flow's disposition as block

#### Scenario: A verdict for an unregistered flow is refused
- **WHEN** a verdict is carried out for a flow_id that was never registered
- **THEN** the flow table returns an error rather than recording a disposition

### Requirement: The process enforcers carry out kill and deny-exec, fail-safe
The enforcement layer MUST carry out KILL_PROCESS by terminating the target process by pid,
and MUST REFUSE to act on pid ≤ 1 (the kernel and init), on its own process, or on a
non-numeric target. It MUST carry out DENY_EXEC by recording a deny for an exec handle
through a controller the permission handler applies, and MUST error when there is no
controller or no target rather than silently allowing the execution. Both MUST use the
existing targeted-enforcer interface, receiving only the verdict in the Decision.

#### Scenario: A kill terminates the target but refuses dangerous pids
- **WHEN** the kill enforcer is asked to enforce KILL_PROCESS on a pid
- **THEN** a normal target process is terminated, while pid ≤ 1, the enforcer's own pid, and a non-numeric target are refused; and a deny with no controller errors rather than allowing the execution

### Requirement: The engine selects the enforcement target by event kind
The engine MUST supply an enforcer the target appropriate to the event's kind: the process id for a
process event (so a process-terminating enforcer can act) and the resolved path for a file event.
A process-terminating enforcer MUST be registrable under the enforcement opt-in, and when a decision
is to terminate a process, the engine MUST carry it out against the event's process id, refusing to
terminate itself or an init-level process, and auditing a refused or failed termination.

#### Scenario: A kill decision terminates the named process and never the engine
- **WHEN** the engine processes a process event with a terminate decision, and separately a process event naming the engine's own process
- **THEN** the named process is terminated while the engine refuses to terminate itself, and both the termination and the refusal are audited
