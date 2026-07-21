## Context

D106 parsed a syslog line; nothing received one. The listener is the I/O half, and UDP is
testable rootless.

## Goals / Non-Goals

**Goals:** a runnable UDP listener that parses datagrams to a sink, survives garbage, shuts
down cleanly.

**Non-Goals:** privileged-port bind / redirect; TCP/TLS syslog; pipeline wiring.

## Decisions

**A bad datagram is dropped and counted, never fatal.** One malformed packet from one noisy
source must not stop ingest — an ingest loop that dies on bad input is a denial-of-service
waiting to happen. The drop count is exposed (atomic) so a flood of unparseable input is
visible, not silent (D28).

**Configurable address, unprivileged by default.** The standard port is 514 (privileged),
but the address is a parameter so the listener runs on a high port without root; the
privileged bind and the transparent redirect that steers traffic to it are deployment
concerns, as with the other connectors' data-plane halves.

**Context-cancel shutdown.** Closing the socket on ctx.Done unblocks the blocking read, and
Serve distinguishes a clean shutdown (ctx cancelled → nil) from a real read error.

## Risks / Trade-offs

- **UDP loses datagrams under load** — inherent to syslog-over-UDP; TCP framing (RFC 6587)
  is the reliable-delivery follow-up.
- **The sink is not yet the pipeline.** Received messages are delivered to a callback; the
  classifier/audit wiring is a follow-up, kept separate so the listener is proven on its own.
