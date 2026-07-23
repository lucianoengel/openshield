## ADDED Requirements

### Requirement: The transparent inline mode can install its own TPROXY redirect rules

The system SHALL be able to install, opt-in, the firewall and routing rules that redirect forwarded TCP
flows into the transparent inline listener (a mark-based routing rule, a divert route in a dedicated routing
table, and a mangle TPROXY rule per configured destination port), so the transparent inline plane is
deployable without hand-crafted out-of-band firewall configuration. The rules MUST be installed and removed
idempotently, confined to a dedicated firewall chain and routing table so teardown never disturbs unrelated
operator rules, and removed on shutdown. Installing the rules is root-only (CAP_NET_ADMIN); where it fails,
the system MUST log the failure and continue running the inline listener rather than fail closed (the
operator may install the rules out of band).

#### Scenario: A redirected flow reaches the listener via self-installed rules
- **WHEN** the TPROXY rules are installed and a forwarded TCP flow to a watched port arrives
- **THEN** it is redirected into the transparent listener and decided by the pipeline (dropped if blocked, spliced if allowed)

#### Scenario: The rules are removed cleanly
- **WHEN** the rules are removed
- **THEN** the dedicated firewall chain and routing table are torn down and unrelated operator rules are untouched

#### Scenario: A rule-install failure does not take the plane down
- **WHEN** the TPROXY rules cannot be installed
- **THEN** the system logs the failure and keeps the inline listener running (rules may be installed out of band)
