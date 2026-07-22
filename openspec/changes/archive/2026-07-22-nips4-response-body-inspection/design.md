## Context

`forward` does `io.Copy(w, resp.Body)` — the response streams through unread. NIPS-4 buffers it (bounded),
classifies it, and then delivers it. The request path already shows the shape (buffer → classify via
`gw.Process` → act); the response reuses it with an INGRESS event and an observe-only disposition.

## Goals / Non-Goals

**Goals**
- Buffer the response body up to the cap (keeping the prefix so an over-cap response can still be
  forwarded), gzip-decode for classification, classify via `gw.Process` as INGRESS, audit.
- Opt-in flag; fail-open on over-cap / error.
- Prove classify+audit+deliver, the over-cap uninspected path, and fail-open.

**Non-Goals**
- Blocking a sensitive response in flight (response-enforcement ordering — a follow-up).
- Multipart decode beyond gzip (DLP-8 follow-up).
- True streaming classification (buffered up to the cap here; over-cap is the honest bound).

## Decisions

### D1 — Buffer up to the cap, keep the prefix, forward the original bytes
A response can't be refused (413) the way a request can — it is the server's answer. So the reader keeps
what it read: within the cap, the full body is buffered, classified, and forwarded verbatim; over the
cap, the buffered prefix plus the unread remainder are streamed through UNINSPECTED and the gap is
audited (like an uninspected tunnel, D78). The client always gets the exact upstream bytes — inspection
never corrupts or truncates the delivered response.

### D2 — Decode gzip for classification, forward the original encoding
Content-Encoding gzip means the wire bytes are compressed; classifying them would scan noise. So a
gzipped response is decompressed (bounded, decompression-bomb-safe) into the text the detectors see,
while the ORIGINAL compressed bytes are what get forwarded (the client's Accept-Encoding was honored by
the origin). A decode failure degrades to classifying the raw bytes — never a failure of delivery.

### D3 — Classify as an INGRESS event through the same pipeline
The response body becomes a `gw.Process` call with direction INGRESS and the response body — the same
classify → policy → audit path as the request, so a response detection lands in the ledger with the flow
metadata and the policy can (later) act on it. Observe-only by default (D1): no enforcer registered means
the response is classified and audited but always delivered.

### D4 — Opt-in, fail-open, default unchanged
Response inspection buffers every response, so it is opt-in (`SetInspectResponses`) — default off keeps
the current streaming behavior and performance byte-for-byte. When on, every failure direction forwards
the response (D73/D17): an over-cap response, a read error, or a classify error delivers the response and
audits the outcome, never a denial of the client's traffic.

## Risks / Trade-offs

- **Buffering latency/memory** — a response is held to the cap before delivery when inspection is on;
  the cap bounds memory, and streaming classification is the noted refinement. Opt-in contains the cost.
- **Over-cap responses uninspected** — the honest bound; audited as a gap, not silent.

## Migration Plan

Additive: one Proxy flag + a branch in `forward` (the off path is the existing code), a bounded-read
variant, gateway-binary wiring. No proto/core change; default behavior unchanged.

## Open Questions

- Whether response blocking should replace the body with a policy page or reset the connection. Deferred
  with the response-enforcement follow-up.
