

## Purpose

Acting on a Decision: the closed set of enforcers (encrypt-local, kill, deny-exec, flow verdicts), the
rule that a Decision is recorded BEFORE enforcement and the enforcement audited after, and the reversal
path for any action that transforms data. Post-decision enforcement CONTAINS, it does not prevent. It
also owns the emergency disable — affirmatively engaged, reachable from the shipped binaries, signed and
replay-proof when fleet-wide, four-eyes to publish — which downgrades enforcement to observation while
detection and audit continue, recording every suppression.

## Requirements

### Requirement: Agents report their actual enforcement state

An agent's liveness signal SHALL carry whether its enforcement is disabled and the highest fleet-control
sequence it has applied. The reported state SHALL be the agent's ACTUAL state, so an agent disabled by a
local break-glass file is visible — the control plane has no other way to learn that.

#### Scenario: A disabled agent is visible
- **WHEN** an agent reports that enforcement is disabled
- **THEN** the fleet summary counts it as disabled

#### Scenario: A locally disabled agent is visible
- **WHEN** an agent is disabled by a local file and has applied no fleet control
- **THEN** it is still counted as disabled

#### Scenario: The latest report wins
- **WHEN** an agent reports a new state
- **THEN** the summary reflects the newer state and the agent is counted once

### Requirement: The fleet summary answers arrival and lag

The system SHALL report how many agents are enforcing, how many are disabled, and how many have not
applied the current control. Publication is best-effort, so without this an operator cannot tell a
delivered disable from an undelivered one.

#### Scenario: Agents behind the current control are counted
- **WHEN** some agents have applied an older sequence than the current control
- **THEN** they are reported as not caught up

### Requirement: Silence is not reported as compliance

The summary SHALL reflect only what agents have reported. An agent that has gone silent MUST NOT be
counted as enforcing or as disabled on the strength of an old report being absent; detecting absence
remains the overdue mechanism's responsibility.

#### Scenario: The summary does not infer state for unseen agents
- **WHEN** an agent has never reported
- **THEN** it contributes nothing to the summary rather than a default state

### Requirement: The emergency disable is reachable from the shipped binaries

Every component that ENFORCES SHALL install the kill switch, watch its local break-glass file, and — when
given a control-plane key and a broker — accept signed fleet-wide control. The control plane SHALL provide
an operator-local means of issuing one.

This is a requirement about WIRING, and it is stated separately because the mechanism existing is not the
same as the mechanism being reachable: a kill switch that no command installs, a channel no command
subscribes to, and a control nothing can sign together look, from outside, exactly like a feature that was
never built — while its unit tests report that it works.

Accepting fleet control SHALL NOT depend on enrollment. A component that cannot publish telemetry is not
the one that should be impossible to stop.

#### Scenario: An issued fleet disable stops a running component enforcing
- **WHEN** an approved, signed fleet disable is published
- **THEN** every running component subscribed to the channel stops enforcing, keeps detecting and
  auditing, and continues running

#### Scenario: Both enforcement call sites honour the same control
- **WHEN** a fleet disable is published
- **THEN** the network component and the endpoint component both apply it

#### Scenario: The local break-glass path works without a control plane
- **WHEN** the break-glass file appears on a host with no broker and no control-plane key
- **THEN** that host stops enforcing, and names the reason the file gave

#### Scenario: Absence of the break-glass file is never engagement
- **WHEN** no break-glass file exists
- **THEN** enforcement continues

#### Scenario: An unapproved fleet disable is never published
- **WHEN** a disable is issued without an approved four-eyes approval bound to its control id
- **THEN** nothing is signed or sent

### Requirement: An enforcement action that transforms data is reversible

Where enforcement makes a subject's data unreadable, the product SHALL ship the means to reverse it. An
irreversible containment is indistinguishable, to the person whose data it was, from destruction.

Reversal SHALL NOT destroy the transformed data, and SHALL identify which key a given artifact requires
rather than failing as a decryption error.

#### Scenario: An encrypted file is recovered
- **WHEN** an operator holding the appropriate key recovers an encrypted file
- **THEN** the original content is restored to a new location and the encrypted form is left intact

#### Scenario: Recovery never overwrites
- **WHEN** the destination already exists
- **THEN** recovery refuses before decrypting anything

#### Scenario: The artifact names the key it needs
- **WHEN** the wrong kind of key is supplied
- **THEN** the refusal names the kind required

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

<!-- restored from 2026-07-21-add-encrypt-local-enforcer -->

### Requirement: A policy deciding encrypt-local routes to the enforcer and is audited
The engine MUST route an `ENCRYPT_LOCAL` Decision to a registered encrypt-local enforcer, encrypt the
target on disk, and audit the enforcement outcome, so enforcement is never silent (D14).

#### Scenario: Encrypt-local flows decision to encrypted file, audited
- **WHEN** a policy decides `ENCRYPT_LOCAL` for an event whose file is on disk and the encrypt-local
  enforcer is registered
- **THEN** the engine records the Decision, encrypts the file in place, and appends an enforcement
  outcome to the audit ledger
- **AND** an end-to-end test asserts the file is encrypted on disk and the outcome is recorded

<!-- restored from 2026-07-21-add-encrypt-local-enforcer -->

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

<!-- restored from 2026-07-21-add-encrypt-local-escrow -->

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

<!-- restored from 2026-07-21-add-encrypt-local-escrow -->

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

<!-- restored from 2026-07-21-add-enforcement-dispatch -->

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

<!-- restored from 2026-07-21-add-enforcement-dispatch -->

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

<!-- restored from 2026-07-21-enforcer-no-symlink -->

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

<!-- restored from 2026-07-21-gateway-http-proxy -->

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

<!-- restored from 2026-07-21-hips-process-enforcers -->

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

<!-- restored from 2026-07-21-network-gateway-skeleton -->

### Requirement: The engine selects the enforcement target by event kind
The engine MUST supply an enforcer the target appropriate to the event's kind: the process id for a
process event (so a process-terminating enforcer can act) and the resolved path for a file event.
A process-terminating enforcer MUST be registrable under the enforcement opt-in, and when a decision
is to terminate a process, the engine MUST carry it out against the event's process id, refusing to
terminate itself or an init-level process, and auditing a refused or failed termination.

#### Scenario: A kill decision terminates the named process and never the engine
- **WHEN** the engine processes a process event with a terminate decision, and separately a process event naming the engine's own process
- **THEN** the named process is terminated while the engine refuses to terminate itself, and both the termination and the refusal are audited

<!-- restored from 2026-07-22-hips5a-enforce-target-by-kind -->

### Requirement: The kill enforcer protects critical processes and resists pid reuse
The process-terminating enforcer MUST refuse to terminate a critical process — init, the service
manager, the remote-access daemon, the database, the container runtime, and the platform's own fleet
binaries — identified by a TRUSTED identity that the target cannot forge: the process's real
executable (not a self-settable process name), protected only when that executable is owned by root
and not writable by non-owners. A process that merely renames itself (its `comm`/`argv[0]`) to a
critical name MUST still be terminable — the protection MUST NOT be grantable by self-naming. The
enforcer MUST also refuse its own process and init-level pids. The termination MUST target the
specific process instance so that a pid recycled between the decision and the kill is not terminated
in place of the intended process; a process that has already exited MUST be a no-op rather than an
error.

#### Scenario: A kill decision spares a critical process and resists reuse
- **WHEN** a terminate decision names a critical process, and separately a non-critical process
- **THEN** the critical process is not terminated and the refusal is auditable, the non-critical process is terminated against its specific instance, and a recycled or already-exited pid is not terminated in place of another process

#### Scenario: A self-renamed process does not gain immunity
- **WHEN** a non-critical process sets its name to a critical one (e.g. `sshd` or a fleet binary name) but its real executable is not a root-owned critical binary
- **THEN** the enforcer still terminates it — the critical-process protection is keyed on the trusted executable identity, not the self-reported name

<!-- restored from 2026-07-22-hips8-trusted-critical-identity -->

### Requirement: An engaged emergency disable downgrades enforcement to observation

While the emergency disable is engaged, a Decision carrying an enforcing action SHALL NOT reach any
enforcer. It SHALL be recorded as observed instead. One implementation SHALL serve every enforcement call
site, so no path can be left enforcing while the switch is engaged.

#### Scenario: An enforcing decision is not enforced
- **WHEN** the switch is engaged and a decision would block, deny or quarantine
- **THEN** no enforcer is invoked for it

#### Scenario: A non-enforcing decision is unaffected
- **WHEN** the switch is engaged and a decision only alerts
- **THEN** its handling is unchanged

#### Scenario: Disengaging restores enforcement
- **WHEN** the switch is disengaged
- **THEN** subsequent enforcing decisions reach their enforcers again

<!-- restored from 2026-07-26-plat9-emergency-disable -->

### Requirement: Detection and audit continue while enforcement is disabled

Engaging the switch SHALL NOT stop classification, decision-making or the audit trail. The record of what
would have been enforced is what an operator needs afterwards, and a switch that also stops the trail is a
blindfold rather than a safety control.

#### Scenario: The ledger still records the decision
- **WHEN** an enforcing decision is suppressed
- **THEN** the decision is still recorded

<!-- restored from 2026-07-26-plat9-emergency-disable -->

### Requirement: Every suppression is recorded, and so is the switch itself

Each suppressed enforcement SHALL be recorded individually, and engaging or disengaging the switch SHALL
itself be recorded with its reason and source. A silent kill switch is indistinguishable from a product
that has stopped working.

#### Scenario: A suppression is counted and attributable
- **WHEN** enforcement is suppressed
- **THEN** the occurrence is counted and reports the reason the switch is engaged

#### Scenario: Engaging is recorded
- **WHEN** the switch is engaged
- **THEN** the reason and the source that engaged it are recorded

<!-- restored from 2026-07-26-plat9-emergency-disable -->

### Requirement: The switch must be affirmatively engaged

If the switch's state cannot be determined, enforcement SHALL continue and the failure SHALL be reported.
A read error, a missing file or an unreachable store MUST NOT disable enforcement.

#### Scenario: An unreadable source does not disable enforcement
- **WHEN** the switch's source cannot be read
- **THEN** enforcement continues and the error is reported

#### Scenario: Absence is not engagement
- **WHEN** no break-glass file exists and no setting is present
- **THEN** enforcement continues

<!-- restored from 2026-07-26-plat9-emergency-disable -->

### Requirement: Fleet-wide operational control is a distinct, signed message type

Fleet-wide control SHALL use a vocabulary separate from response intents. Intent verbs cause enforcement;
this stops it, and one message type carrying both meanings fails in the most dangerous direction when a
consumer mishandles the discriminator.

#### Scenario: A signed disable stops enforcement on a consumer
- **WHEN** a consumer receives a validly signed, in-date, in-sequence disable
- **THEN** enforcement stops there, and detection continues

#### Scenario: A signed restore resumes enforcement
- **WHEN** a validly signed restore is received
- **THEN** enforcement resumes

<!-- restored from 2026-07-26-plat9e-fleet-disable -->

### Requirement: A replayed control is refused

A consumer SHALL refuse a control whose sequence is at or below the highest it has applied. A captured,
genuinely signed disable verifies perfectly every time it is re-sent, so the signature alone cannot bound
it; without a sequence an attacker could re-disable a fleet after an operator restored enforcement.

#### Scenario: Re-sending a captured disable changes nothing
- **WHEN** a disable that was already applied is re-sent after a restore
- **THEN** it is refused and enforcement stays on

<!-- restored from 2026-07-26-plat9e-fleet-disable -->

### Requirement: A control must be in date, in vocabulary, and verifiable

A control SHALL be refused if its signature does not verify, its version is unknown, its verb is
unspecified, or it is expired or carries no expiry. Every refusal SHALL leave enforcement ON.

#### Scenario: An unverifiable control changes nothing
- **WHEN** a control fails signature verification
- **THEN** enforcement is unchanged

#### Scenario: A control with no expiry is refused
- **WHEN** a control carries no expiry
- **THEN** it is refused, because a disable that cannot lapse is a product that is off with nobody
  remembering having turned it off

<!-- restored from 2026-07-26-plat9e-fleet-disable -->

### Requirement: Publishing a fleet disable requires four-eyes

Publication of a fleet-wide disable SHALL require an approved four-eyes approval bound to that control's
id, with no exemption by impact class — there is no low-impact way to disable a security product
fleet-wide. The check SHALL happen before anything is signed or sent.

#### Scenario: An unapproved disable is never published
- **WHEN** no approved approval exists for the control id
- **THEN** nothing is signed or sent

#### Scenario: The approval binds to the exact control
- **WHEN** an approval is granted
- **THEN** it authorizes only the control whose id it names

<!-- restored from 2026-07-26-plat9e-fleet-disable -->
