# NIPS-3: wire the DNS connector into the engine pipeline

## Why

The DNS connector had two proven halves that were never joined: a UDP `Listener` (D128) that
receives and parses live query datagrams to a sink, and a `ToEvent` producer that turns a
parsed query into a `NetworkSubject` Event. But no binary connected them — the listener ran
only in its own test, so live DNS resolution never actually entered the pipeline. Egress policy
on resolved names and DNS-tunnelling detection (`dns.TunnelScore`) were parser-only capabilities
with no running path. This is the same built-but-unwired gap the honesty bucket exists to close.

A second, smaller gap surfaced on wiring: the listener's sink dropped the datagram's **source
IP** (`ReadFromUDP`'s address was discarded), so an Event produced from it could not say *who*
asked — a network decision without a source is not actionable.

## What Changes

- **The DNS listener carries the source IP to its sink**: `sink func(srcIP string, q Query)`.
  The receive loop now passes `addr.IP.String()` alongside the parsed query.
- **The engine gains a DNS source**: when `OPENSHIELD_DNS_LISTEN` is set, `cmd/openshield-engine`
  binds the listener and feeds each parsed query — as a `NetworkSubject` Event with a minted
  monotonic flow id and the source IP — into the SAME event channel the file watchers use. Live
  resolution then runs classify → policy → decide → audit exactly like a file event. It is an
  additional SOURCE, additive to file watching, and observe-only (D1) — no enforcement path.
  The source goroutine is tracked so the event channel is not closed while it produces, and a
  send races context cancellation so shutdown never blocks the receive loop.

This modifies the `dns-connector` capability (the sink now carries the source) and the
`endpoint-engine` capability (the engine runs the DNS source). No core interface changes.

## Impact

- Affected specs: `dns-connector`, `endpoint-engine`
- Affected code: `internal/connectors/dns/listen.go` (+ test),
  `cmd/openshield-engine/dnssource.go` (new, testable helper), `cmd/openshield-engine/main.go`.
- Not in scope (stated): the privileged bind / transparent redirect that steers real :53
  traffic to the listener (a deployment concern, as for all connectors); wiring the syslog and
  SMTP listeners the same way (identical shape — follow-ups); a DNS-only engine mode (file
  watching stays required; DNS is additive).
