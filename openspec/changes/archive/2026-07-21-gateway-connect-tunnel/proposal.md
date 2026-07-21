## Why

The proxy (D73) handles only plain-HTTP absolute-URI requests. An HTTPS client
first sends `CONNECT host:443`, which the proxy does not handle — so HTTPS does not
work through it at all. This change adds CONNECT handling with a blind TCP tunnel:
HTTPS transits the proxy opaquely. It is the groundwork before TLS interception —
the proxy relays ciphertext and inspects nothing, a stated coverage gap that
interception (N1.3b) closes.

## What Changes

- `Proxy.ServeHTTP` dispatches `CONNECT` to a new `handleConnect`: hijack the client
  connection (`http.Hijacker`), dial the upstream `host:port` (`net.DialTimeout`),
  reply `200 Connection Established`, and relay bytes both directions with two
  `io.Copy` goroutines that close both connections when either finishes.
- The tunnel inspects NOTHING — tunneled HTTPS bodies are not classified. Each
  tunnel is logged at info ("not inspected — TLS interception is N1.3b") so the
  coverage gap is operationally visible rather than silent (D16).
- Plain-HTTP behaviour (D73) is unchanged.

## Capabilities

### Modified Capabilities
- `network-gateway`: the proxy handles `CONNECT` and tunnels HTTPS opaquely, so
  HTTPS transits the proxy. It does NOT inspect tunneled traffic — interception is
  a later increment.

## Impact

- `internal/gateway.Proxy` gains CONNECT handling; `docs/decisions.md` D74. No
  change to the pipeline, the ledger, the flow table, or plain-HTTP handling.
- Proven with REAL TLS: an httptest TLS upstream + the Proxy + a real proxy client
  trusting the upstream cert — an HTTPS POST succeeds end to end through the tunnel
  AND the ledger stays empty (the tunneled body was not classified — the honest
  gap); a dead upstream returns 502.
- NOT in scope (stated plainly): TLS interception / MITM, a SEPARATE interception
  CA (never the fleet mTLS CA — a MITM root can impersonate the whole internet to
  the fleet, a far larger blast radius), on-the-fly SNI leaf minting, and the
  do-not-intercept list — all N1.3b; a metadata-only audit of tunneled flows (a
  visibility follow-up); the worker pool. Respects D1/D49, D73, D16.
