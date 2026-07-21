## Context

The endpoint splits parsing into `openshield-worker`, a separate binary run under
seccomp with no network (D29/D35), because a parser bug in a privileged/network
process is host compromise (ClamAV CVE-2025-20260 is the precedent). The worker
reads `ClassifyRequest` frames whose `oneof subject` is `path | file_handle`, opens
the file ITSELF with unprivileged credentials, and returns detector hits — never
matched content (D10/D29). The engine (D48) holds a `classifier` interface the
worker satisfies.

D70's gateway instead calls `internal/classify` IN-PROCESS on the body it read off
the socket (D71). The gateway is network-capable, so this is the same RCE surface
the worker exists to remove — just in a different node.

## Goals / Non-Goals

**Goals:**
- Move gateway body classification into the sandboxed worker.
- Give the worker an inline-content classify path, bounded exactly like the file
  path, shared with the endpoint.
- The gateway process no longer links the parser.

**Non-Goals:**
- The real HTTP proxy listener + socket-backed FlowTable (N1.2b); TLS interception
  (N1.3).
- A worker POOL — one mutex-serialized worker suffices until the concurrent
  listener exists (noted).
- Weakening the endpoint invariant — the agent stays path-only.

## Decisions

**`bytes content` is a new `oneof subject` variant, not a reused field.** The
endpoint passes `path` and the worker opens the file itself so attacker bytes never
enter the CAP_SYS_ADMIN agent. That invariant belongs to the AGENT (its code sends
path-only; `check-agent-deps` keeps parsers out of its binary), NOT to the proto.
The gateway is a different node — network-capable, unprivileged — that MUST hold
the body to proxy it; it has already read the bytes, so handing them to the worker
does not create new exposure, it MOVES the parser (regex today, format parsers
later — the real RCE surface) into the sandbox. A distinct `content` variant keeps
the two callers legible: "worker, open this file" vs "worker, parse these bytes I
already hold".

**The content path reuses the exact bounding of the file path.** `worker.Handle`
switches on the subject; the content case wraps `bytes.NewReader(content)` in the
same `limitReader` (max_bytes ceiling → truncated flag) and calls the same
`Classifier`. A decompression/backtracking bomb in an inline body hits the same
limit as one in a file — no second, weaker path. Empty content is a valid input
(classify → no hits → ALLOW), distinguished from "no subject" (an error) by the
oneof type, not by an empty-slice check.

**The gateway depends on the classifier INTERFACE, not `internal/classify`.**
`internal/gateway` drops its `*classify.Classifier` for the same private
`classifier` interface the engine uses. Production wires a `*privileged.Worker`
(`NewFromWorker`); tests wire a `fakeWorker`. The body-classify stage builds a
`ClassifyRequest{Content: body, MaxBytes: …}`, calls the worker, surfaces
`resp.Error` as a stage failure (D17: a worker error is not a clean result), and
builds the content-free `LocalClassification` from `resp.Hits` exactly as the
engine does. Because the gateway no longer imports `internal/classify`, the network
process does not link the parser — asserted by a dependency-graph test, the
`check-agent-deps` discipline applied to the gateway.

**One shared worker is concurrency-safe now; a pool is deferred.**
`Worker.Classify` holds a mutex (one request in flight, synchronous framing), so
concurrent `gateway.Process` calls serialize through it correctly. That serializes
throughput — fine for the skeleton, and the concurrent HTTP listener (N1.2b) is
where a worker POOL earns its complexity. Noted, not silently assumed away.

## Risks / Trade-offs

- **Sending the full body over IPC is a copy per request.** Correct for the
  boundary; a shared-memory hand-off is a possible optimisation once throughput
  matters. Stated, not premature-optimised.
- **The proto now lets any caller send bytes to the worker.** This does not weaken
  the endpoint: the agent's code still sends path-only and its binary still
  excludes parsers (`check-agent-deps`). The new variant is exercised by the
  gateway, a node that legitimately holds bytes. The invariant that matters —
  parsing happens only in the sandbox — is strengthened, not weakened.
