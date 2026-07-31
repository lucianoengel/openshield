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

### Requirement: A live DNS query MUST carry a tunnelling signal into the policy input

For each observed DNS query event, the engine MUST derive a tunnelling likelihood score from the
queried name and expose it to policy evaluation as a typed input, so that a policy can decide on
it.

The input MUST be ABSENT for events that are not DNS queries, rather than present with a
default value — an absent input tells a policy that nothing was assessed, and a fabricated value
tells it something was.

The score MUST be derived from the name only. No query payload, and no content beyond the
metadata the connector already parsed, may be introduced by the derivation.

#### Scenario: A tunnelling name is scored

- **WHEN** a DNS query is observed whose name carries long, high-entropy labels
- **THEN** the policy input for that event MUST include a tunnelling score

#### Scenario: A non-DNS event carries no tunnelling input

- **WHEN** a filesystem or process event is evaluated
- **THEN** the tunnelling input MUST be absent from its policy input

### Requirement: The default policy MUST alert on a high tunnelling score and MUST NOT block

The shipped default policy MUST raise an ALERT when a DNS query's tunnelling score reaches the
configured threshold, and MUST NOT deny the query.

Denial is reserved for an operator raising the action deliberately. A heuristic over a single
query, with no session context, that automatically denied name resolution would turn one false
positive into a resolution outage.

#### Scenario: A tunnelling query alerts

- **WHEN** a DNS query scores at or above the configured tunnelling threshold
- **THEN** the decision MUST be ALERT
- **AND** an audit entry MUST be recorded

#### Scenario: An ordinary query does not alert

- **WHEN** a DNS query for a short, low-entropy name is observed
- **THEN** the decision MUST NOT be an alert arising from the tunnelling rule

### Requirement: The tunnelling threshold MUST be refused when outside the score's range

The tunnelling threshold MUST be a validated configuration setting constrained to the range the
score can take, and a value outside that range MUST be refused when it is set.

A threshold a score can never reach silently disables a detector while the process reports it as
enabled — the failure mode is indistinguishable from "nothing suspicious happened" on a console.

#### Scenario: An out-of-range threshold is refused at save

- **WHEN** an operator sets the tunnelling threshold to a value outside the score's range
- **THEN** the setting MUST be refused with an error naming the field

### Requirement: A DNS decision's audit entry MUST NOT contain the queried name

An audit entry arising from a DNS query MUST NOT record the queried name or any label of it.

This requirement is more acute than the general content-free rule it follows from: in a DNS
tunnel, the exfiltrated data IS the name. An evidence trail that recorded it would republish the
exfiltration it exists to detect, into the system's most copied and longest-retained store.

#### Scenario: The tunnelled payload does not reach the ledger

- **WHEN** a DNS query encoding data in its subdomain labels is decided upon
- **THEN** no audit entry may contain the encoded labels
<!-- synced from nips3-dns-tunnel-signal -->

### Requirement: Catalogued service names resolve to the gateway

The resolver SHALL answer configured service names with a configured address — normally the ZTNA
gateway's — so a client reaches an internal service THROUGH the broker with no client configuration.

The bypass guard closes the wrong path and does nothing about the right one: the client still has to be
TOLD to use the broker, which in practice means a hosts file, a VPN profile, or an internal DNS server
somebody else maintains. Together the two make brokered access ordinary rather than opt-in — the guard
makes going around it fail, and this makes going through it automatic.

THIS IS CONVENIENCE, NOT ENFORCEMENT, and documentation SHALL NOT let the two be read as one control. A
client that hardcodes an IP, caches an old answer, or uses DoH/DoT never asks this resolver anything. The
firewall guard is what binds; this removes the reason anybody would need to work around it.

A CATALOGUED NAME SHALL OUTRANK THE BLOCK LIST, and the collision SHALL be logged. Of the two readings —
"send this user to the broker" and "this name is malware" — the one an operator explicitly wrote for this
deployment wins; the alternative makes a catalogued service silently unreachable with nothing naming the
cause.

ONLY THE REQUESTED ADDRESS FAMILY SHALL BE ANSWERED. Returning an A record to an AAAA query is not merely
useless: a dual-stack client reads it as "no AAAA" and may still reach the real address over IPv6, which
is the direct path this exists to remove. An unmatched family SHALL get an empty NOERROR — the name
exists, not in this family — never NXDOMAIN.

Names SHALL match case-insensitively and with or without the trailing root dot, because resolver
libraries differ about the dot and a table written one way answering nothing for the other looks exactly
like the feature being off.

The answer TTL SHALL be short. The address is infrastructure configuration, and a long TTL keeps clients
sending traffic to a gateway that has moved with no way to shorten it after the fact.

A MALFORMED TABLE ENTRY SHALL be refused, and a malformed table SHALL prevent the resolver from starting
— the opposite of the fail-to-wire everything else here uses. The rest degrades toward "name resolution
still works"; a half-loaded split table degrades toward "some clients silently reach protected services
directly", which is the outcome the guard and this exist together to prevent.

#### Scenario: A catalogued name resolves to the gateway
- **WHEN** a client queries a configured service name
- **THEN** it is answered locally with the configured address, and the sinkhole and forwarding still work
  for everything else

#### Scenario: Only the requested family is answered
- **WHEN** a client asks for AAAA and only a v4 address is configured
- **THEN** it receives an empty NOERROR rather than an A record

#### Scenario: A catalogued name outranks the block list
- **WHEN** a name is both catalogued and on the threat feed
- **THEN** it is answered with the gateway address and the collision is logged

#### Scenario: A malformed table refuses to start the resolver
- **WHEN** the split-horizon configuration contains an entry that cannot be parsed
- **THEN** the resolver does not start rather than answering for only some of the names
