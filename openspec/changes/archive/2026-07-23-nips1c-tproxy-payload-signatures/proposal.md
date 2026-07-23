## Why

The transparent inline plane now decides a flow on its destination IP (increment 1, D225) and its TLS
SNI (increment 2, D226) — but not on the flow's actual **payload**. The NIPS-2 content-signature engine
(D221) already scans request bodies for malicious patterns in the sandboxed worker, but only on the
*explicit-proxy* HTTP path. This increment wires that engine into the transparent plane: the bytes
already peeked for SNI are also handed to the worker's signature engine, so a malicious **cleartext
payload** (an exploit string, a C2 beacon marker, a known-bad request) is dropped inline. That completes
the detection story — the full NIPS-2 engine now runs on transparently-intercepted flows.

## What Changes

- **The peeked payload is classified.** `handleFlow` already peeks the flow's initial bytes; those bytes
  are now passed to the decision as the flow's body, so `Gateway.Process` runs them through the sandboxed
  worker's content-signature (and DLP) engine. A content-signature threat match on the payload → the
  policy blocks → the flow is dropped inline.
- **Bounded, and honest about it.** Only the peeked prefix (`maxPeek`) is scanned — a signature past the
  peek window is missed, the same budget trade the NIPS-2 engine already makes. TLS payload is encrypted,
  so this catches **cleartext** flows; TLS flows are covered by the SNI (increment 2). Stated plainly.
- **Fail-open unchanged:** a worker/pipeline error forwards the flow (increment 1's fail-open); the
  peeked bytes are still replayed to the destination so an allowed flow is byte-for-byte transparent.

## Capabilities

### New Capabilities
<!-- none — extends the network-gateway transparent inline mode. -->

### Modified Capabilities
- `network-gateway`: the transparent inline mode additionally classifies the peeked payload through the
  sandboxed content-signature engine, so a flow whose cleartext payload trips a signature is dropped
  inline — not only a bad destination IP or SNI.

## Impact

- **Code:** `internal/gateway/tproxy.go` — `FlowHint` carries the peeked payload; the gateway-backed
  decider sets `Request.Body = payload` so the existing body-classify → worker → content-signature →
  threat → policy path fires. No proto, no migration, no new dependency.
- **Testing:** a real-worker integration test (built `openshield-worker` with `OPENSHIELD_NIPS_RULES` + a
  content signature) drives a flow whose peeked payload contains the pattern through the gateway-backed
  decider → dropped; a clean payload → spliced. The kernel TPROXY redirect is unchanged from D225/D226,
  so no new VM run is required (the new logic is userspace).
- **Deferred:** streaming inspection beyond the peek window (increment 1 is a bounded prefix); TLS
  interception to see encrypted payload (a larger, separate effort); HTTP request-line/header structured
  parsing.
