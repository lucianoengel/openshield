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

