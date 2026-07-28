

## Purpose

Getting the product onto a host correctly: systemd units that enforce the privilege split, each
component isolated under its own user, one idempotent install script, a watchdog-safe upgrade, and a
database role for the running product that cannot weaken the ledger's append-only guard. Releases are
reproducible and carry a signed digest manifest that fails on any tampering; the signing key never
ships. Schema skew is detected and reported, and a NEWER schema does not prevent startup.

## Requirements

### Requirement: Schema skew is detected and reported

A binary SHALL compare the migrations it embeds against those the database has applied and report whether
it is behind, level, or running against a schema NEWER than it knows. The newer case arises whenever a
binary is rolled back after a migration, and it MUST NOT be silent: the binary is then reading a schema
whose changes it cannot know.

#### Scenario: A rolled-back binary reports the skew
- **WHEN** the database has more migrations applied than the binary embeds
- **THEN** the skew is reported, naming how many migrations the binary does not know

#### Scenario: A level binary reports no skew
- **WHEN** the applied and embedded migration counts match
- **THEN** no skew is reported

#### Scenario: Skew is observable without reading logs
- **WHEN** a binary is running against a newer schema
- **THEN** the condition is exposed as a metric

### Requirement: A newer schema does not prevent startup

A binary meeting a newer schema SHALL start. Refusing would make rollback impossible after any migration —
worse than the risk it avoids, and a direct contradiction of the requirement that a deployment can roll
back.

#### Scenario: Startup proceeds under skew
- **WHEN** the database schema is newer than the binary
- **THEN** the binary starts, having reported the skew

### Requirement: The systemd units enforce the privilege split
The packaged units MUST run the privileged agent with only `CAP_SYS_ADMIN` (not the full root
capability set) and the parser worker as an unprivileged user with no capabilities and the hardening
drop-in. The split MUST be enforced by the unit configuration, not left to the deployer.

A privilege boundary that depends on a deployer remembering to drop capabilities erodes to
everything-as-root. Encoding least privilege in the units a deployer inherits by default is what
keeps D13/D29's split real in production, not just in the code.

#### Scenario: The units are well-formed and least-privilege
- **WHEN** the agent and worker units are validated
- **THEN** the agent unit bounds capabilities to CAP_SYS_ADMIN and the worker unit runs as an
  unprivileged user with an empty capability bounding set and the hardening drop-in
- **AND** `systemd-analyze verify` accepts every unit

<!-- restored from 2026-07-21-add-packaging -->

### Requirement: Install is one idempotent script; upgrade is watchdog-safe
Installation MUST be a single idempotent script that goes from a built tree to installed, enabled
units — creating the unprivileged worker user, placing binaries and units, reloading systemd — with
no hand-editing. The documented upgrade path MUST rely on the fail-open watchdog so a restart under
load cannot hang the machine.

Manual multi-step installation is where a privilege boundary gets skipped; one script that does it
right, every time, is the mitigation. And an upgrade that could hang a machine is one operators will
avoid, leaving stale agents — the watchdog (D18) is what makes restart routine.

#### Scenario: Re-running the installer is safe
- **WHEN** the install script is run twice
- **THEN** the second run updates in place without duplicating users or failing
- **AND** it refuses to run without root, with a clear message, and does not auto-start the agent

#### Scenario: The upgrade path is documented as watchdog-safe
- **WHEN** the upgrade procedure is read
- **THEN** it states that restarting the agent is safe under load because the fail-open watchdog
  answers the kernel regardless of pipeline state (D18)

<!-- restored from 2026-07-21-add-packaging -->

### Requirement: The gateway runs under its own isolated hardened unit
The gateway's systemd unit MUST run under a dedicated non-login user (never root, never the monitored
account), with NoNewPrivileges, an empty capability bounding set, strict system protection, and a
private 0700 state directory holding its secrets (the ledger signer and, when interception is on, the
interception-CA private key) — the same isolation the engine has. The installer MUST create the gateway
user and install and enable the gateway unit.

#### Scenario: The gateway unit isolates its secret-holder
- **WHEN** the gateway unit is inspected
- **THEN** it runs under the dedicated gateway user with no capabilities, no new privileges, strict
  system protection, and a private state directory

<!-- restored from 2026-07-21-deploy-honesty-hardening -->

### Requirement: The installer does not enable the stub agent
The installer MUST NOT enable the agent unit while the agent binary is a stub that exits non-zero (the
deferred inline-blocking component), so systemd does not run a guaranteed-failing service.

#### Scenario: The installer does not enable the stub agent
- **WHEN** the installer's enable step is inspected
- **THEN** it enables the gateway (and the other real services) and does not enable the stub agent

<!-- restored from 2026-07-21-deploy-honesty-hardening -->

### Requirement: A service catalog is parsed from configuration
The gateway MUST parse its internal-service catalog from a configuration string mapping service names to
upstream URLs, and MUST reject a malformed entry or an unparseable URL rather than silently skipping it,
so a misconfigured route fails loudly instead of leaving a service unexpectedly unreachable.

#### Scenario: A valid catalog resolves its services and a bad entry is rejected
- **WHEN** a catalog string of name=url pairs is parsed
- **THEN** each named service resolves to its upstream, and a malformed entry or bad URL is an error

<!-- restored from 2026-07-21-gateway-access-mode-binary -->

### Requirement: The engine is installed and isolated under a dedicated user
The installer MUST install a systemd unit and create a DEDICATED non-login system user for the engine
— the process holding the ledger signer key and OPA — so it runs neither as root nor as the monitored
account, and the signer state is owned by that user in a directory only it can write. The privilege
split is enforced by the units, not left to the deployer (D45).

The unit MUST run unprivileged (no broad capabilities, NoNewPrivileges) and confine writes to a state
directory. The installer MUST also install the anchor service and timer so external anchoring runs.
Host root still defeats at-rest protection (D16); this closes the wrong-user erosion, not a root
compromise.

#### Scenario: The engine unit isolates the signer-key holder
- **WHEN** the installer runs
- **THEN** it creates the dedicated engine user, installs the engine unit that runs under that user
  (not root, not the monitored account) with NoNewPrivileges and no broad capabilities and a
  state directory for the signer, and installs the anchor service + timer
- **AND** a build-time test asserts the engine unit's isolation and that install.sh installs the user
  and the engine + anchor units, so a regression that drops the isolation fails the build

<!-- restored from 2026-07-21-isolate-engine-packaging -->

### Requirement: The running product connects to the ledger DB as a non-owner role
The shipped deployment configuration MUST run the long-running binaries under a NON-OWNER database
role that can perform the application's writes (append the ledger, write the aggregate tables) but
cannot ALTER the schema or disable the append-only trigger, so the database-level append-only
boundary is not owner-bypassable in the running product. Schema migration MUST be a separate owner-
privileged step, and the application MUST start safely as the non-owner role by skipping migration
when the database is already migrated. The non-owner role MUST be a real login role that cannot
escalate back to the owner.

#### Scenario: The app role can write but cannot disable the append-only boundary
- **WHEN** a binary connects as the provisioned non-owner application role and attempts to disable the append-only trigger or delete a ledger row, including after resetting its role
- **THEN** the writes the application needs succeed while the disable/delete attempts are refused, and the same operation succeeds only for the database owner

<!-- restored from 2026-07-22-plat6b-wire-restricted-db-role -->

### Requirement: A release build is reproducible

Building the same commit twice with the release procedure SHALL produce byte-identical artifacts. Build
flags SHALL exclude anything that varies between builds — absolute paths, build timestamps and VCS state
that is not the commit itself.

Reproducibility is what makes a signature meaningful: without it, nobody but the signer can establish that
an artifact corresponds to the source, and the signature attests only that the signer had *a* binary.

#### Scenario: Two builds of one commit agree
- **WHEN** the same commit is built twice with the release procedure
- **THEN** the artifacts' digests are identical

#### Scenario: Build metadata does not leak the build environment
- **WHEN** a release artifact is inspected
- **THEN** it contains no absolute path from the machine that built it

<!-- restored from 2026-07-26-plat6-signed-reproducible-release -->

### Requirement: A release carries a signed digest manifest

A release SHALL include a manifest naming every artifact with its SHA-256 digest, and a detached signature
over that manifest. Signing the manifest rather than each artifact means one signature covers the set —
including which artifacts exist, so an artifact cannot be *added* to a release unnoticed.

#### Scenario: The manifest covers every shipped artifact
- **WHEN** a release is produced
- **THEN** every artifact in it appears in the manifest, and every manifest entry exists

#### Scenario: The manifest signature verifies
- **WHEN** the manifest is checked against the release public key
- **THEN** verification succeeds

<!-- restored from 2026-07-26-plat6-signed-reproducible-release -->

### Requirement: Verification fails on any tampering

Verification SHALL fail if any artifact's bytes differ from its recorded digest, if the manifest differs
from what was signed, or if an artifact named in the manifest is absent. A failure SHALL name what did not
match.

#### Scenario: A modified artifact is rejected
- **WHEN** one artifact's bytes are altered
- **THEN** verification fails and names that artifact

#### Scenario: A modified manifest is rejected
- **WHEN** the manifest is altered after signing
- **THEN** signature verification fails

#### Scenario: An artifact added after signing is rejected
- **WHEN** a file is added to the release directory that the manifest does not name
- **THEN** verification reports it rather than ignoring it

<!-- restored from 2026-07-26-plat6-signed-reproducible-release -->

### Requirement: The signing key never ships

The private signing key SHALL NOT appear in the repository or in the release output. Only the public key
is distributed.

#### Scenario: The release output contains no private key
- **WHEN** a release is produced
- **THEN** no private key material is present in its output

<!-- restored from 2026-07-26-plat6-signed-reproducible-release -->

### Requirement: Release verification MUST support an out-of-band pinned signing key

The release verification command MUST accept an operator-supplied ed25519 public key and, when one is
supplied, MUST verify the release manifest's signature against THAT key.

The public key file distributed inside the release directory MUST NOT be consulted when a pinned key
is supplied, under any condition — including the pinned key being unreadable or malformed, which MUST
be a hard failure rather than a fallback.

#### Scenario: A release re-signed with another key is refused under a pinned key

- **WHEN** an attacker modifies an artifact and re-signs the entire release with a key of their own,
  replacing the public key shipped in the release directory
- **AND** an operator verifies with a pinned key naming the project's real public key, obtained out of band
- **THEN** verification MUST fail, naming the signature as the reason

#### Scenario: A genuine release verifies under its pinned key

- **WHEN** a release is verified with a pinned key corresponding to the key that signed it
- **THEN** verification MUST succeed

#### Scenario: A malformed pinned key is a hard failure

- **WHEN** the pinned key file cannot be read or is not an ed25519 public key
- **THEN** the command MUST fail
- **AND** MUST NOT fall back to the public key shipped inside the release directory

### Requirement: Unpinned release verification MUST state what it did not establish

When no pinned key is supplied, the release verification command MUST report that it checked the
integrity of the artifact set and did NOT establish that the project signed it, and MUST say how to
check authenticity.

This is the D31 rule applied to the supply chain: an operator who runs a verification command and
sees success will believe the strongest claim the command could plausibly be making, so a limit that
is not stated becomes a false belief.

#### Scenario: Verifying without a pinned key announces the limit

- **WHEN** a release is verified with no pinned key
- **AND** the artifact set is internally consistent
- **THEN** the command MUST succeed
- **AND** MUST report that authenticity was not established and that a pinned key establishes it

### Requirement: Release verification MUST report the key it verified against

The verification command MUST report a fingerprint of the public key whose signature it accepted, so
that two operators can establish they verified against the same key rather than each against whatever
key was shipped to them.

#### Scenario: The verified key is identifiable in the output

- **WHEN** a release verifies successfully, pinned or unpinned
- **THEN** the output MUST include a fingerprint of the public key that was used

<!-- synced from release-verify-key-pinning -->
