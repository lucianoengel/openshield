## Why

The gateway classifies the request body but copies the *response* through untouched. That is a real DLP
hole: a server returning a spreadsheet of customer records, a misconfigured API leaking secrets, or an
attacker exfiltrating via a response the gateway never reads — all invisible today. NIPS-4 inspects the
response body too, so a sensitive response is detected and audited, closing the "we watch what goes up
but not what comes down" gap.

## What Changes

- The forward path buffers the response body (memory-bounded), gzip-decodes it for classification, and
  runs it through the gateway pipeline as an INGRESS event — so the response's content is classified and
  the decision is audited, exactly as the request is.
- Opt-in (`SetInspectResponses`), so the default streaming behavior and performance are unchanged until
  an operator turns it on.
- Fail-open preserved (D73/D17): an over-cap response is forwarded UNINSPECTED (a stated, audited
  coverage gap — a response can't be refused like a request), and a read/classify error forwards the
  response rather than breaking it.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `network-gateway`: the forward proxy inspects the response body (classify + audit), not only the
  request — closing the inbound DLP gap while preserving the egress fail-open.

## Impact

- **Code:** a `Proxy.inspectResponses` flag + response classification in `forward` (bounded read that
  keeps its prefix, gzip decode, INGRESS event through `gw.Process`); gateway-binary wiring. Proven with
  a real httptest upstream: a response carrying a CPF is classified and audited while still being
  delivered; an over-cap response is forwarded uninspected (audited gap) and intact; a read error fails
  open; inspection OFF is byte-for-byte the current streaming behavior.
- **Scope note (honest):** this increment CLASSIFIES + AUDITS the response (observe). **Blocking a
  sensitive response** in flight (replacing an already-started response) has response-enforcement
  ordering subtleties and is a noted follow-up — observe-first matches the request path's original
  landing (D1). **Multipart decode** (shared with DLP-8) beyond gzip is a follow-up; **streamed** (vs
  buffered) classification for very large responses is the memory/latency refinement, with the over-cap
  path the honest bound today.
