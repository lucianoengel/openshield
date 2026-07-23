## Why

The transparent inline connector (NIPS-1 increment 1, D225) decides a redirected flow on L4 metadata
only — the destination IP. That misses the common case: a malicious or policy-blocked domain served from
a **shared CDN IP** (Cloudflare, Fastly, S3, …) cannot be blocked by dst-IP without collateral damage.
The domain is in the TLS **ClientHello SNI** — sent in the clear before the handshake. Peeking it lets
the inline plane block by **domain** (the IOC feed already matches domains), turning "block a bad IP"
into "block a bad hostname," which is what actually maps to threat intel.

## What Changes

- **Peek the first bytes of an intercepted flow** (bounded, short deadline) without consuming them, and
  **extract the SNI** from a TLS ClientHello with a defensive, bounds-checked parser (no allocation from
  attacker-supplied lengths).
- **Decide on the SNI:** the flow's Request now carries `Host = SNI`, so the existing IOC domain match
  and any host policy apply — a flow to a blocked domain is dropped even on a shared IP.
- **Replay on splice:** the peeked bytes (the ClientHello) are prepended to the upstream copy, so an
  allowed flow is byte-for-byte transparent — the server sees the original handshake.
- **Fail-open preserved:** a non-TLS flow, no SNI, a peek timeout, or a parse failure falls back to the
  L4-metadata decision (increment 1) and splices — never a broken handshake, never a dropped flow on a
  peek error.

## Capabilities

### New Capabilities
<!-- none — extends the network-gateway transparent inline mode. -->

### Modified Capabilities
- `network-gateway`: the transparent inline mode additionally recovers the flow's SNI hostname (from the
  TLS ClientHello) and decides on it, so a flow to a blocked domain on a shared IP is dropped; an allowed
  flow is spliced byte-for-byte (the peeked handshake is replayed).

## Impact

- **Code:** `internal/gateway/sni.go` (a defensive ClientHello SNI extractor + tests); `tproxy.go`
  (peek → SNI → decide-with-host → replay-on-splice). No proto, no migration, no new dependency.
- **Testing:** SNI extraction unit tests over real ClientHello bytes (+ non-TLS / truncated / no-SNI →
  empty, no panic); a peek/replay handler test (a denied SNI drops; an allowed flow's peeked bytes reach
  the origin) over loopback, no root; the existing gated VM TPROXY test extended with a TLS client to a
  denied SNI.
- **Deferred (increment 3):** content-signature inspection of the flow payload via the worker (this
  increment is SNI/host only — a still-lightweight in-gateway metadata parse, like the existing HTTP host
  handling); HTTP/1.1 Host-header peek for cleartext flows; QUIC/TLS1.3-encrypted-ClientHello (ECH).
