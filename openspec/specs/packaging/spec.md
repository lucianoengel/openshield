# packaging Specification

## Purpose
systemd units and an idempotent installer that ENACT the privilege split (agent bounded to CAP_SYS_ADMIN; worker unprivileged + hardening; server ordinary), with a watchdog-safe upgrade path - so the security posture is inherited by default, not reconstructed by hand.
## Requirements
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

### Requirement: The installer does not enable the stub agent
The installer MUST NOT enable the agent unit while the agent binary is a stub that exits non-zero (the
deferred inline-blocking component), so systemd does not run a guaranteed-failing service.

#### Scenario: The installer does not enable the stub agent
- **WHEN** the installer's enable step is inspected
- **THEN** it enables the gateway (and the other real services) and does not enable the stub agent

### Requirement: A service catalog is parsed from configuration
The gateway MUST parse its internal-service catalog from a configuration string mapping service names to
upstream URLs, and MUST reject a malformed entry or an unparseable URL rather than silently skipping it,
so a misconfigured route fails loudly instead of leaving a service unexpectedly unreachable.

#### Scenario: A valid catalog resolves its services and a bad entry is rejected
- **WHEN** a catalog string of name=url pairs is parsed
- **THEN** each named service resolves to its upstream, and a malformed entry or bad URL is an error
