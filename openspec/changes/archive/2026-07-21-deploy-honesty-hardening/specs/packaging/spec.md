# packaging delta

## ADDED Requirements

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
