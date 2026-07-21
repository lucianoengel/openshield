## Context

`Proxy.ServeHTTP` (D73) treats every request as a plain-HTTP forward-proxy request
(absolute URL, buffered body, classify → decide → forward). HTTPS does not work
that way: the client sends `CONNECT host:443`, expects `200 Connection
Established`, then runs a TLS handshake through the tunnel end to end with the
origin. A proxy that wants to SEE the HTTPS body must terminate that TLS itself
(MITM) — a large, security-sensitive step. Before that, the proxy must at least not
break HTTPS.

## Goals / Non-Goals

**Goals:**
- Handle `CONNECT` so HTTPS transits the proxy (blind tunnel).
- Keep plain-HTTP handling unchanged.
- Make the fact that tunneled traffic is uninspected explicit and logged.

**Non-Goals:**
- TLS interception / MITM, the interception CA, SNI leaf minting, the
  do-not-intercept list — all N1.3b.
- A metadata-only audit record of tunneled flows (a visibility follow-up).
- The worker pool.

## Decisions

**`CONNECT` gets a blind tunnel; the proxy inspects nothing.** On `CONNECT
host:port` the handler hijacks the client connection, dials the upstream, replies
`200 Connection Established`, and copies bytes both ways until either side closes.
The bytes are ciphertext — the TLS session is between the client and the origin —
so the pipeline is bypassed entirely. This is the ONLY correct behaviour without
interception: the alternative (refusing CONNECT) breaks all HTTPS. The cost is that
tunneled HTTPS bodies are not classified, which is stated and logged, not hidden.

**The tunnel is logged, so the coverage gap is visible.** Each tunnel logs the host
and "not inspected — TLS interception is N1.3b". An operator can see which egress
transited uninspected; the audit trail's silence about tunnel BODIES is a known,
surfaced limit (D16), not an accident. A metadata-only audit record (a NETWORK_FLOW
event with the host and no body) is a reasonable next step, noted, not built here —
it would need care not to read as an inspected "ALLOW".

**Interception is deliberately deferred, and its CA is deliberately separate.** TLS
interception means the gateway presents a certificate the client trusts for an
arbitrary host — the power to impersonate any site. Signing those leaves with the
FLEET mTLS CA would give that CA internet-wide impersonation power over the fleet, a
far larger blast radius than fleet identity needs. So interception (N1.3b) will use
a SEPARATE interception CA, deployed as a trusted root only where interception is
authorised. Recording this now keeps the tunnel increment from quietly becoming the
foundation for reusing the wrong CA later.

## Risks / Trade-offs

- **Tunneled HTTPS is a coverage gap.** The dominant egress path (HTTPS) is
  uninspected until N1.3b. Stated plainly and logged; not papered over.
- **A blind tunnel to an arbitrary host is an open relay risk.** The proxy dials
  whatever host the client names. Scoping (allowed-destination policy, auth) is a
  deployment concern noted for the connector; the skeleton dials as a forward proxy
  does, which is the expected behaviour behind an authenticated perimeter.
- **Hijacking ties the tunnel to HTTP/1.1 semantics.** Fine for a forward proxy;
  HTTP/2 CONNECT and QUIC are out of scope and unneeded here.
