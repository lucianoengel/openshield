## ADDED Requirements

### Requirement: Self-installed TPROXY rules are bound to the inline server's lifecycle

When OpenShield installs the TPROXY redirect rules itself, the rules MUST exist only while the transparent
inline server is running: the system SHALL remove the rules the moment the server's accept loop returns —
for any reason, an unexpected stop as well as a clean shutdown — so a stopped listener never leaves forwarded
traffic redirected into a dead socket. The rules MUST NOT be removed when installation did not succeed (the
operator may own the rules out of band). This is the fail-open availability invariant applied to the
redirect: a redirect must never outlive the thing it redirects into.

#### Scenario: Rules are removed when the inline server stops unexpectedly
- **WHEN** the transparent inline server's accept loop returns while the process keeps running
- **THEN** the self-installed TPROXY rules are removed and forwarded traffic falls back to direct routing

#### Scenario: Rules are removed on clean shutdown too
- **WHEN** the process is shutting down and the server's context is cancelled
- **THEN** the self-installed TPROXY rules are removed
