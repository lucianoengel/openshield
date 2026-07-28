## Why

The estate-log ingest path is **UDP only**, and it is the one ingest path in the product where an
operator has no way to choose reliability — while carrying third-party evidence.

Three specific consequences, all verified in the code:

- **The loss is structurally invisible.** `Listener.Dropped()` counts datagrams that FAILED TO PARSE — a
  line the application received. A datagram the kernel discards because the receive buffer is full never
  reaches the application, so nothing counts it and nothing logs it. That is exactly the silent gap D31
  forbids: nobody can tell *"that device sent nothing"* from *"we could not read what it sent"*.
- **A rich event is the one most likely to vanish.** The receive buffer is sized to the line bound and a
  larger datagram is TRUNCATED BY THE KERNEL, after which the parser rejects it. A CEF event with a
  realistic extension set exceeds a safe UDP payload, so the failure mode for the INTERESTING events is:
  truncated, unparseable, counted as a parse error, gone — and it reads as a malformed device rather than
  an MTU problem.
- **The sender is not authenticated.** Anything that can reach the port can inject events into what the
  product invites operators to treat as an audit store. For evidence, fabrication is worse than loss.

The product asserts the opposite discipline everywhere else: the endpoint spool exists so an outage causes
a GAP THAT FILLS IN rather than loss, and durable telemetry ingest acknowledges only after persistence,
with at-most-once being an explicit documented opt-out. External logs get at-most-once with no opt-in to
anything better.

## What Changes

- **TCP ingest (RFC 6587)**, supporting both framings real senders use — octet-counting
  (`MSG-LEN SP MSG`) and non-transparent framing (LF-terminated). TCP supplies what UDP cannot: delivery
  to the receiver and BACKPRESSURE, so a receiver that cannot keep up slows its senders instead of
  silently discarding.
- **TLS ingest (RFC 5425) with MUTUAL authentication**, reusing the existing `tlsconf` material and its
  `RequireAndVerifyClientCert`. A device without an operator-issued certificate is refused at the
  handshake, which is what makes the store's contents attributable.
- **An oversized message is REFUSED AND COUNTED, never truncated.** Over a stream the receiver can say
  "this message exceeds the bound" instead of silently keeping a prefix — so a too-large event is a
  reported error against a named sender rather than a mystery parse failure.
- **UDP stays**, unchanged, for devices that cannot do better — and is documented as best-effort and
  NOT evidentiary.

## Capabilities

### Modified Capabilities

- `cef-syslog-ingest`: the transport becomes a stated property — which guarantees each carries, what is
  authenticated, and which is admissible as evidence.

## Impact

- `internal/connectors/syslog` — a stream listener beside the datagram one, sharing the same parse sink so
  CEF/RFC 5424 handling has ONE implementation.
- `cmd/openshield-server`, `internal/config` — two new listen settings; TLS material is the server's
  existing `OPENSHIELD_TLS_*`.
- No proto change, no migration. UDP behaviour is unchanged.
- **Honest limit, to be stated in the spec rather than implied away:** TCP removes kernel-level silent
  drop and adds backpressure. It does NOT give an application-level acknowledgement that an event was
  PERSISTED — a process killed with data in its buffers still loses it. The claim is that loss now
  requires a crash or an explicit refusal, both of which are visible, rather than a buffer quietly
  filling.
