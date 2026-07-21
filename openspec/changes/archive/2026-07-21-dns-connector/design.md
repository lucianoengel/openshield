## Context

The gateway connector (D73) separates HTTP parsing from sockets so the wire-format surface
is tested without I/O. The DNS connector follows the same shape: a pure parser + Event
producer, no sockets here.

## Goals / Non-Goals

**Goals:** parse a DNS query into a metadata-only Event; a tunneling/exfil heuristic; no
core change.

**Non-Goals:** the socket listener / transparent redirect (external-gated); responses;
EDNS/DNSSEC; SMTP.

## Decisions

**Parse only the question, never chase compression pointers.** A query's QNAME is not
compressed, so a pointer byte in the question is malformed — the parser rejects it rather
than following it, which also removes the pointer-loop DoS. The decoded name is bounded to
255 octets (RFC 1035), so a crafted message cannot drive an unbounded loop/allocation.

**The queried name is metadata in sni_host.** NetworkSubject.sni_host already carries "the
flow's destination name" (TLS SNI / HTTP Host); a DNS query name is the same kind of
metadata — what host the flow is about — so it reuses that field rather than widening the
contract. A policy decides on it; it is never body content (D10/D29).

**Tunneling = length AND entropy (a product).** A covert channel needs BOTH a long label
AND high per-character entropy; a long dictionary word is not exfil and a short random
token is not a channel. The score multiplies the two signals so either being low keeps the
score low — the mutation test flips product→sum and catches that a sum would flag normal
names. It is a SIGNAL for a policy, not a verdict.

## Risks / Trade-offs

- **The heuristic is approximate.** It flags a shape, not a certainty; a policy sets the
  threshold and can allow-list known high-entropy CDNs. Tuning against real traffic (T-015)
  is the calibration; a downstream classifier could refine it.
- **No live capture yet.** This is the parser + producer; a socket listener + transparent
  redirect is the external-gated data-plane half, deferred with its privileges.
