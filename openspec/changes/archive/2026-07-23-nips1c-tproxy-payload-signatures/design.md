## Context

`handleFlow` (D225/D226) peeks a flow's initial bytes (for SNI) and replays them on splice. The
gateway's `bodyClassifyStage` sends `Request.Body` to the sandboxed worker, which runs the NIPS-2
content-signature engine (D221) and returns `threat_matches`, projected onto `st.Threats` for the
policy. The transparent decider currently sets `Host = SNI` but leaves `Body` empty, so the payload is
never classified.

## Goals / Non-Goals

**Goals:** classify the peeked payload through the worker's content-signature engine and drop a flow whose
cleartext payload trips a signature — inline, preserving fail-open and byte-for-byte splicing.

**Non-Goals:** streaming inspection past the peek window; TLS interception (encrypted payload); structured
HTTP parsing. All deferred/stated.

## Decisions

1. **Reuse the peeked bytes as the flow body.** `FlowHint` gains `Payload []byte` (the peeked prefix).
   `handleFlow` sets it from the same buffer it peeks for SNI — no extra read. The gateway-backed decider
   sets `Request.Body = hint.Payload`, so the existing `bodyClassifyStage → worker → content-signature →
   threat → policy` path fires with zero new pipeline code. A content-signature threat match → the policy
   blocks → `handleFlow` drops the flow.

2. **Bounded by the peek window, consistent with the engine's own budget.** Only `maxPeek` bytes are
   scanned; the NIPS-2 engine already scans a bounded prefix, so this is the same trade — a signature past
   the window is missed, never a hang. Documented, not hidden.

3. **Cleartext only, by construction.** For a TLS flow the peeked bytes are the ClientHello (a handshake),
   so no content signature matches — the SNI (increment 2) is the signal there. For a cleartext flow the
   peeked bytes are the actual payload. Setting `Body` unconditionally is correct: it simply yields no
   content-signature match on a ClientHello.

4. **Fail-open and splice unchanged.** A worker/pipeline error still forwards the flow (increment 1); the
   peeked bytes are still replayed to the destination (increment 2). This increment only adds an input to
   the decision, never a new drop path outside the policy.

## Risks / Trade-offs

- **A worker round-trip per flow setup.** The decision now classifies the peeked payload in the worker,
  adding latency to flow setup. Bounded by `maxPeek` and the worker's own budget; acceptable and
  identical in character to the explicit proxy's existing per-request worker classify. Fail-open bounds
  the worst case (a slow/errored worker forwards the flow).
- **The peek window bounds coverage.** A payload whose malicious content is past `maxPeek` is not caught
  inline. Same as the NIPS-2 scan budget; streaming inspection is a follow-up.
- **No effect without a configured ruleset.** With no `OPENSHIELD_NIPS_RULES` in the worker, the payload
  classify yields no content-signature match and the flow is decided exactly as before — inert until
  configured, consistent with the rest of NIPS-2.
