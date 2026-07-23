## ADDED Requirements

### Requirement: Transparently redirect local DNS to the sinkhole resolver

The system SHALL be able to transparently redirect locally-originated UDP port 53 traffic to the local
sinkhole resolver, so that a client which has not been configured to use the resolver is still subject to
the sinkhole. The redirect MUST be installed and removed idempotently (a re-install after an unclean
shutdown MUST NOT fail on a stale rule) and MUST be confined to a dedicated firewall table so removing it
never disturbs unrelated operator firewall rules. The redirect is a root-only (CAP_NET_ADMIN) capability;
where it cannot be installed the system MUST log the failure and continue serving explicitly-configured
clients rather than fail to start.

#### Scenario: An unconfigured client's blocked query is sinkholed transparently
- **WHEN** the transparent redirect is installed and a client that points at some other DNS server queries a blocked domain
- **THEN** the query is redirected to the local resolver and answered NXDOMAIN, without the client being configured to use the resolver

#### Scenario: The redirect is removed cleanly
- **WHEN** the redirect is removed
- **THEN** the dedicated firewall table is deleted and normal DNS traffic is no longer redirected

### Requirement: The resolver's own upstream queries escape the redirect (loop-break)

The transparent redirect MUST NOT capture the resolver's own forwarded upstream queries, which are
themselves port 53 traffic; capturing them would loop every forwarded query back into the resolver and
break all normal name resolution. The system SHALL break the loop with a firewall mark: the resolver marks
its upstream socket and the redirect rule exempts marked packets. A resolver configured without a mark MUST
behave exactly as before (no redirect, plain upstream forwarding).

#### Scenario: A normal query is still resolved through the redirect
- **WHEN** the transparent redirect is installed with the loop-break mark and a client queries a non-blocked domain
- **THEN** the resolver forwards the query to the real upstream (its marked socket escaping the redirect) and relays the upstream's answer to the client

#### Scenario: Without the mark exemption the loop breaks resolution
- **WHEN** the redirect rule omits the mark exemption and captures all port 53 traffic
- **THEN** the resolver's own forwarded query is redirected back into the resolver and a non-blocked query is never answered
