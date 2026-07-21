# packaging delta

## ADDED Requirements

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
