## ADDED Requirements

### Requirement: The sinkhole redirect covers forwarded (gateway) DNS traffic

The system SHALL be able to transparently redirect FORWARDED UDP port 53 traffic (client DNS passing through
the host as a gateway) to the local sinkhole resolver, so the sinkhole protects clients behind the gateway
and not only the gateway host's own queries. The forwarded redirect MUST be installed and removed
idempotently in its own dedicated firewall chain so teardown never disturbs unrelated operator rules, MUST
exclude loopback traffic, and — because the resolver's own upstream queries are locally-originated and never
traverse the forwarded (prerouting) path — MUST NOT require the loop-break mark that the local redirect
needs. Installing it is root-only (CAP_NET_ADMIN); where it cannot be installed the system MUST log the
failure and continue serving explicitly-configured clients.

#### Scenario: A forwarded client's blocked query is sinkholed
- **WHEN** the forwarded redirect is installed and a client behind the gateway queries a blocked domain
- **THEN** the forwarded query is redirected to the local resolver and answered NXDOMAIN

#### Scenario: A forwarded client's normal query is resolved
- **WHEN** a client behind the gateway queries a non-blocked domain
- **THEN** the resolver forwards it to the real upstream and the client receives the answer

#### Scenario: The forwarded redirect is removed cleanly
- **WHEN** the forwarded redirect is removed
- **THEN** its dedicated firewall chain is torn down and forwarded DNS is no longer redirected
