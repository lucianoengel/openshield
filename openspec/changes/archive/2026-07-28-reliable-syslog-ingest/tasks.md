## 1. The stream listener

- [x] 1.1 `syslog.ListenStream(addr, sink, tlsConf)` accepting TCP, and TLS when a config is supplied,
      sharing the datagram listener's sink.
- [x] 1.2 RFC 6587 framing: octet-counted and newline-terminated, detected per message.
- [x] 1.3 An over-bound message is counted and skipped, never truncated; the connection survives it.
- [x] 1.4 Bounds: connection cap, read deadline, and the existing admission rate limiter.

## 2. Wire it

- [x] 2.1 Two settings — a TCP listen address and a TLS listen address — leader-only, beside the
      existing CEF-over-syslog listener.
- [x] 2.2 The startup line states the transport and, for each, what it guarantees.

## 3. Prove it

- [x] 3.1 Unit: both framings; an over-bound message refused and counted; a malformed message followed
      by a good one on the same connection.
- [x] 3.2 Integration: a CEF event over TCP is stored and searchable.
- [x] 3.3 Integration: over TLS, a sender WITH an operator certificate is ingested; one with NO
      certificate and one with an UNTRUSTED certificate are refused at the handshake and store nothing.
- [x] 3.4 Mutations: accept a message over the bound (truncation returns); drop client-cert verification.

## 4. Land

- [x] 4.1 `make quick`, package tests, the targeted integration scenarios.
- [x] 4.2 Record in `docs/unwired-audit.md`; commit with a D-number, archive WITH sync, check CI.
