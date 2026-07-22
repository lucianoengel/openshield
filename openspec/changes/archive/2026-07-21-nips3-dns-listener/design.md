## Context

D101 gave a pure DNS query parser + Event producer; D108 gave the syslog UDP listener as the
template. NIPS-3 is the DNS listener, the same shape.

## Goals / Non-Goals

**Goals:** a runnable UDP listener parsing datagrams to a sink, surviving garbage, clean
shutdown.

**Non-Goals:** privileged bind/redirect; pipeline wiring; TCP/DoT/DoH.

## Decisions

**Mirror the syslog listener (D108).** Same proven shape: a UDP bind, parse each datagram to a
sink, drop+count malformed (atomic counter, observable), context-cancel shutdown. Consistency
across the connector data-plane halves.

**A bad datagram is dropped and counted.** DNS is UDP and noisy; one unparseable packet from one
host must not stop resolution monitoring. The drop count is exposed so a flood is visible.

## Risks / Trade-offs

- **UDP only** — TCP DNS (large responses, zone transfers) and encrypted DNS (DoT/DoH) are
  follow-ups; UDP covers the vast majority of resolution and the exfil channel.
- **Sink not yet the pipeline** — parsed queries go to a callback; the classifier/policy wiring
  (with TunnelScore) is a follow-up, kept separate so the listener is proven on its own.
