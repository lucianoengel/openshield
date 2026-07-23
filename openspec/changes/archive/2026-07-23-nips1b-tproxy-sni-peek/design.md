## Context

`handleFlow` (D225) decides a redirected flow via `DecideFunc(ctx, origDst, src)` and, on allow, splices
the client to the original destination. The pipeline already matches a domain when `Request.Host` is set
(`SniHost` → the IOC domain match). The missing input is the SNI, which is in the ClientHello the client
sends first — readable by peeking the connection before the decision.

## Goals / Non-Goals

**Goals:**
- Extract the SNI from a TLS ClientHello with a defensive parser, decide on it (domain block), and replay
  the peeked bytes so an allowed flow is byte-for-byte transparent.
- Preserve fail-open: any peek/parse problem falls back to the L4 decision and splices.

**Non-Goals (increment 3):** content-signature inspection of the payload via the worker; HTTP Host-header
peek for cleartext; QUIC / encrypted ClientHello (ECH).

## Decisions

1. **A defensive, standalone ClientHello SNI parser (`sni.go`).** It walks the TLS record header
   (content-type 22 handshake, a version, a length), the handshake header (type 1 ClientHello, a length),
   then the fixed ClientHello fields (version, random, session-id, cipher-suites, compression) to the
   extensions, and finds `server_name` (0x0000), returning the host. **Every length is bounds-checked
   against the buffer before use; no slice is sized from an attacker length.** A buffer that is not a TLS
   ClientHello, is truncated, or has no SNI returns `""` — never an error that drops the flow, never a
   panic. This is a metadata parse (a hostname), the same class as the gateway's existing in-process HTTP
   host handling — not content classification (which stays in the worker).

2. **Peek without consuming, then replay.** `handleFlow` reads up to `maxPeek` bytes from the client into
   a buffer under a short read deadline, resets the deadline, extracts the SNI, and decides. On splice,
   the upstream receives `io.MultiReader(bytes.NewReader(peeked), client)` so the ClientHello is
   delivered first and the flow is byte-for-byte transparent. The client→upstream and upstream→client
   copies are otherwise unchanged.

3. **The decision gains the SNI; the L4 path is the fallback.** `DecideFunc` gains a `hint FlowHint{SNI
   string}` argument; the gateway-backed decider sets `Request.Host = hint.SNI`. A flow with no SNI
   decides exactly as increment 1 (dst-IP metadata). The three existing handler unit tests pass an empty
   hint and are unchanged in behavior.

4. **Fail-open on the peek.** If the first read times out (a client that speaks first-server protocols, or
   a slow client) or errors, `peeked` is empty, the SNI is `""`, and the flow decides on metadata and
   splices — a peek must never delay a flow past a short budget or drop it. `maxPeek` bounds memory.

## Risks / Trade-offs

- **Parsing attacker bytes in the network process.** SNI extraction is a tiny bounded parse, written
  defensively (every length checked, no attacker-sized allocation), consistent with the gateway already
  parsing HTTP in-process. Full content classification remains in the sandboxed worker (D72) — this
  increment does not move content parsing into the gateway.
- **A first-byte peek adds a small latency** and assumes the client speaks first (true for TLS/HTTP). A
  server-speaks-first protocol yields a peek timeout → fail-open splice (no SNI, decided on metadata).
  Bounded by the peek deadline.
- **TLS 1.3 Encrypted ClientHello (ECH)** hides the SNI; such flows fall back to the L4 decision. Stated;
  ECH is not yet widespread and is a known limit of all SNI-based controls.
- **The peek buffer is bounded (`maxPeek`)**; a ClientHello larger than the buffer (rare, with many
  extensions) yields no SNI and falls back to L4 — never a partial/incorrect parse.
