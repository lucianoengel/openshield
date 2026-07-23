# dns-sinkhole Specification

## Purpose
The preventive DNS resolver (NIPS-8): it turns DNS from a passive tap into an inline control. It reads
UDP queries, SINKHOLES a policy/IOC-blocked domain (answers NXDOMAIN so the client cannot resolve the
malicious name — RPZ-style), and FORWARDS every other query to a configured upstream, relaying the
response. It FAILS OPEN — a query it cannot parse or classify is forwarded, never dropped or NXDOMAIN'd —
because a resolver that blackholes on uncertainty would break name resolution for the whole fleet. A
local cache, upstream failover, a sinkhole-IP walled garden, and TCP/DoT are follow-ups. A transparent
:53 redirect brings unconfigured clients under the sinkhole with no reconfiguration, using a firewall-mark
loop-break so the resolver's own upstream forwards escape the redirect.

## Requirements
### Requirement: A DNS resolver sinkholes a blocked domain and forwards the rest

The system SHALL provide a DNS resolver that reads a UDP query, and for a domain on the blocked set — or a
subdomain of one — SHALL answer with an NXDOMAIN response built from the query (same transaction id and
question, no answers), so the client cannot resolve the malicious name; for any other domain it SHALL
forward the query to a configured upstream resolver and relay the response unchanged. A sinkholed query
MUST NOT be forwarded to the upstream.

#### Scenario: A blocked domain is sinkholed
- **WHEN** a query for a blocked domain (or a subdomain of one) is received
- **THEN** the resolver answers NXDOMAIN and does not forward the query upstream

#### Scenario: A normal query is forwarded and relayed
- **WHEN** a query for a domain that is not blocked is received
- **THEN** the resolver forwards it to the upstream and relays the upstream's response to the client

### Requirement: The resolver fails open — it never blackholes name resolution

The resolver MUST fail open: a message it cannot parse as a query, or a domain the block set does not
match, MUST be forwarded to the upstream rather than dropped or answered NXDOMAIN. A classification gap or
a malformed input MUST NEVER cause the resolver to refuse a name it is not certain is blocked, because a
resolver that blackholes on uncertainty would break name resolution for the whole fleet.

#### Scenario: An unparseable query is forwarded, not dropped
- **WHEN** a message that cannot be parsed as a DNS query is received
- **THEN** it is forwarded to the upstream (fail-open), not dropped or sinkholed

#### Scenario: An unmatched domain is forwarded
- **WHEN** a query's domain is not on the blocked set
- **THEN** it is forwarded to the upstream and resolved normally

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

### Requirement: The transparent redirect self-heals to direct resolution when the resolver fails

When the transparent DNS redirect is active, the system SHALL continuously probe the local resolver's
liveness and, after a threshold of consecutive failed probes, SHALL remove the redirect so that host DNS
falls back to direct resolution rather than being wedged against a dead resolver. A single failed probe
MUST NOT remove the redirect (the threshold damps flapping). When the resolver recovers, the system SHALL
re-install the redirect. On shutdown the redirect MUST be removed. This is the fail-open availability
invariant applied to the redirect itself: a failure of the control must get out of the way, never take the
host's name resolution down with it.

#### Scenario: A wedged resolver is bypassed, not left wedging DNS
- **WHEN** the resolver stops answering and the failed-probe threshold is reached
- **THEN** the redirect is removed and subsequent DNS queries resolve directly instead of being dropped into the dead resolver

#### Scenario: A single failed probe does not bypass
- **WHEN** the resolver fails a single liveness probe but is answering again on the next
- **THEN** the redirect stays installed (the threshold prevents flapping)

#### Scenario: The redirect is restored when the resolver recovers
- **WHEN** the resolver was bypassed and then answers a liveness probe again
- **THEN** the redirect is re-installed so unconfigured clients are covered again
