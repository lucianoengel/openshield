## Why

NIPS-3 (P1, part). The DNS parser (D101) — the hard part (untrusted-bytes parsing) — is built
and tested, but only the socket front-end was missing, so it could not see live traffic. This
adds the UDP listener, making the DNS connector runnable and unlocking live DNS-exfil / C2-over-
DNS monitoring (the TunnelScore heuristic exists but was unwired to real queries).

## What Changes

- `dns.Listener` (`Listen`, `Serve`, `Addr`, `Dropped`): a UDP socket that parses each datagram
  to a sink; a malformed datagram is dropped and COUNTED (atomic); clean context-cancel
  shutdown; a nil sink is refused. Mirrors the syslog listener (D108).

## Capabilities

### Modified Capabilities
- `dns-connector`: a runnable UDP listener receives and parses live DNS queries.

## Impact

- New `internal/connectors/dns/listen.go`; `docs/decisions.md` D128.
- Proven with a REAL UDP socket: two valid DNS queries (a TXT exfil-shaped name and an A query)
  arrive parsed at the sink; a garbage datagram is dropped, counted, and monitoring survives; a
  nil sink is refused; Serve returns nil on clean shutdown. Race-clean. Guards mutation-tested
  (malformed-delivered-not-dropped; nil-sink).
- NOT in scope (stated): the privileged port-53 bind / transparent redirect (a deployment
  concern — the address is configurable, runs unprivileged on a high port); wiring the sink into
  the pipeline (a parsed query → NetworkSubject Event → policy — the ToEvent producer D101 is
  built; assembling it into a running pipeline with the TunnelScore heuristic is a follow-up);
  TCP DNS / DoT / DoH. One malformed datagram never stops monitoring (D17/D28).
