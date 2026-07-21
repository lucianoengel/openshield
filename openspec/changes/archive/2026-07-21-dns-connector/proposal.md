## Why

The gateway saw HTTP(S), but DNS — a primary egress and exfiltration channel — did not
enter the pipeline. Phase C (network breadth) adds a DNS-query connector so resolution
events flow through the SAME pipeline as file and HTTP events, enabling egress policy on
resolved names and detection of DNS tunneling (a long, high-entropy query name is the
classic covert channel).

## What Changes

- `EVENT_KIND_DNS_QUERY` (additive enum, like the D69 network kinds).
- `internal/connectors/dns`: `ParseQuery` (pure DNS wire-format question decoder, bounded,
  rejects malformed/response/pointer messages); `ToEvent` (NetworkSubject Event, queried
  name as metadata in sni_host); `TunnelScore` (a length×entropy heuristic flagging
  DNS-tunnel/exfil names).

## Capabilities

### Added Capabilities
- `dns-connector`: DNS queries enter the pipeline as metadata-only network events, with a
  tunneling/exfil heuristic.

## Impact

- `proto/…/event.proto` (+1 enum value, regenerated); new `internal/connectors/dns`;
  `docs/decisions.md` D101.
- Proven: a real DNS query message parses to its name + qtype and produces a DNS_QUERY
  NetworkSubject Event (name in sni_host, udp/53); malformed/too-short/response/truncated/
  compression-pointer messages are rejected (never a partial name, D17); the tunnel
  heuristic scores ordinary names low and a base32-encoded exfil label high. Guards
  mutation-tested (label-bound; pointer-in-qname; QR-response-rejection; tunnel product-vs-sum).
- NOT in scope (stated): the UDP:53 socket listener / transparent redirect (the I/O side —
  like the gateway, the parser is separated from sockets; a live listener + nftables/TPROXY
  redirect is the external-gated C1 piece, needing root/network-namespace privileges like
  the fanotify permission mode B2); DNS responses / answer records; EDNS/DNSSEC; an SMTP
  connector (the next C2 candidate). The queried name is METADATA (a policy decides on it),
  never body content (D10/D29); no core interface changed (a new connector + additive enum,
  the D26/D69 fitness pattern).
