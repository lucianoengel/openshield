## Why

The syslog connector (D106) was a pure parser with no way to receive traffic. This
hardening adds the runnable half — a UDP listener — so syslog ingest actually RUNS,
receiving datagrams and delivering parsed messages. UDP ingest is testable unprivileged
(unlike the fanotify permission mode), so the running connector is proven with a real
socket, not deferred.

## What Changes

- `syslog.Listener` (`Listen`, `Serve`, `Addr`, `Dropped`): binds a UDP socket, parses each
  datagram, delivers to a sink; a malformed datagram is dropped and COUNTED (not fatal);
  clean shutdown on context cancel. The drop count is atomic (concurrent read).

## Capabilities

### Modified Capabilities
- `syslog-connector`: a runnable UDP listener receives and parses live syslog datagrams.

## Impact

- New `internal/connectors/syslog/listen.go`; `docs/decisions.md` D108.
- Proven with a REAL UDP socket: two valid datagrams (RFC 3164 + 5424) arrive parsed at the
  sink; a garbage datagram is DROPPED, counted, and ingest keeps running; a nil sink is
  refused; Serve returns nil on clean shutdown. Guards mutation-tested (malformed-delivered-
  not-dropped; nil-sink). Race-clean (the drop counter is atomic).
- NOT in scope (stated): binding the privileged port 514 / transparent redirect (a
  deployment concern — the address is configurable, so it runs unprivileged on a high port);
  TCP syslog (RFC 6587 octet-framing) and TLS (RFC 5425); wiring the sink into the
  pipeline/classifier (the received messages are structured records; classifying their text
  composes with the classifier — a follow-up). One malformed datagram never stops ingest
  (an ingest that dies on bad input is a DoS, D17/D28).
