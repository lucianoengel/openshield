## Context

Found by asking what the UDP listener actually guarantees, after an integration test for it discovered
the transport was UDP at all. The relevant code facts:

- `syslog.Listen` → `net.ListenUDP`; there is no stream path.
- `Listener.Dropped()` counts PARSE failures. Nothing counts a datagram the kernel discarded.
- The read buffer is sized to the line bound, and the code's own comment records that a larger datagram
  "is truncated by the kernel, which the parser then rejects".
- `tlsconf.ServerConfig()` already does `RequireAndVerifyClientCert` at TLS 1.3, and the operator PKI
  (`openshield-provision`) already issues the certificates.

## Decisions

### One sink, two transports

The stream listener shares the `func(Message)` sink with the datagram one, so CEF and RFC 5424 parsing,
the external-log projection and the store have exactly ONE implementation. A second copy of the parse
path is how the two transports would come to disagree about what a message means — the same reasoning
that made the IOC store and the inline NIPS engine share one matcher.

### Both framings, detected per message

RFC 6587 defines octet-counting (`MSG-LEN SP MSG`) and non-transparent framing (LF-terminated), and real
senders use both — rsyslog defaults to one, many appliances to the other. Requiring a single framing is
how a log source ends up not onboarded, which is the failure that matters most here: an un-ingested
source produces no alerts and looks exactly like a quiet one.

Detection is positional and cheap: a message beginning with a digit followed by a space is octet-counted;
anything else is read to the newline. That is what interoperable implementations do, and it is decided
per message rather than per connection so a sender that mixes them still works.

### Refuse an oversized message; do not truncate

Over a datagram the kernel truncates before the application has any say. Over a stream the receiver CAN
say no — so it does: an over-bound message is counted and skipped, and the connection continues. This is
the difference between "a mystery parse failure" and "sender X sent a 9KB message and the bound is 8KB",
and only one of those is actionable.

### Mutual TLS, reusing the server's material

Encryption without client authentication would protect a message in flight and leave the sender anonymous
— which does not address the injection problem, the one that matters for an audit store. `tlsconf`
already requires and verifies a client certificate, so the TLS listener is the existing configuration
applied to a new socket rather than a new trust story.

Reusing `OPENSHIELD_TLS_*` rather than minting ingest-specific settings is deliberate: the server's
identity is the server's identity, and a second set of certificate settings is a second thing to get
wrong, silently, in a place that fails closed only if the operator configured it correctly.

### What this does NOT provide

No application-level acknowledgement of PERSISTENCE. A sender whose write returns has reached the
receiver's socket, not the database; a process killed with buffered data loses it. Claiming end-to-end
durability would need an application ack per message and a sender that honours it — which is what the
agent's own durable ingest does, and which no syslog device implements.

Stated plainly in the spec because the honest claim is narrower than "no loss": **loss now requires a
crash or an explicit refusal, both visible, instead of a buffer quietly filling.**

## Risks / Trade-offs

- **A stream listener is an attack surface a datagram listener is not**: connections persist, so they
  consume memory and file descriptors. Bounded by the existing rate limiter plus a connection cap and a
  read deadline, and by refusing over-bound messages rather than buffering them.
- **Backpressure propagates.** A slow database now slows senders instead of dropping their events. That
  is the point, and it is a behaviour change an operator should know about: with UDP the symptom was
  missing data, with TCP it is a queue on the device.
- **mTLS raises the onboarding cost** — every sender needs a certificate. The plaintext TCP listener
  exists for estates that cannot, and it is honest about what it does not provide.
