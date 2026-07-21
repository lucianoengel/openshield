## Why

D70 shipped the network gateway skeleton but classifies the request body IN-PROCESS
(D71, recorded loudly as a known gap): a parser bug in the network-capable gateway
process is RCE — the exact danger the endpoint's seccomp-sandboxed, network-denied
worker (D29/D35) exists to contain. Before the gateway sees live traffic (N1.2b),
the parser MUST run in the sandbox, not in the process holding the network sockets.
This change closes D71 by giving the worker an inline-content classify path and
repointing the gateway at the worker, mirroring the endpoint exactly.

## What Changes

- `ClassifyRequest` gains `bytes content = 6;` in its `oneof subject` (beside
  `path` and `file_handle`). A network-capable caller that ALREADY holds the body
  (the gateway read it off the socket) hands the bytes to the worker to PARSE. The
  endpoint invariant — the worker opens the file itself and the CAP_SYS_ADMIN agent
  never holds bytes — is the AGENT's discipline (path-only), NOT the proto's; the
  gateway is a different node (network-capable, unprivileged) that must hold the
  bytes to proxy them, so sending them to the worker moves the PARSER (the RCE
  surface) into the sandbox.
- `worker.Handle` classifies the content variant through the SAME bounded
  `limitReader` (max_bytes ceiling, truncated flag) the path variant uses; the path
  behaviour is unchanged; no subject is an error.
- `internal/gateway` holds a `classifier` interface (the same one the engine uses:
  `Classify(ctx, *ClassifyRequest) (*ClassifyResponse, error)`), NOT
  `internal/classify`. The body-classify stage sends `Content = body` to the
  worker-backed classifier, builds the content-free `LocalClassification` from
  `resp.Hits` exactly as before (type+confidence+count, matched text NEVER
  attached, D10/D29), and surfaces `resp.Error` as a stage failure (a worker error
  is not a clean result, D17). `internal/gateway` no longer links the parser.
  `New(classifier, …)` takes the interface; `NewFromWorker(*privileged.Worker, …)`
  is the production constructor, mirroring `engine.NewFromWorker`.

## Capabilities

### Modified Capabilities
- `parser-sandbox`: the worker classifies inline content supplied by a
  network-capable caller — bounded by the same max_bytes ceiling — in addition to
  opening a file by path. The parser stays in the sandbox regardless of who holds
  the bytes.
- `network-gateway`: body classification runs in the sandboxed worker, not
  in-process; the gateway process no longer links the parser (D71 closed).

## Impact

- proto addition (regenerated), `worker.Handle` type switch, `internal/gateway`
  repointed at the worker interface, `docs/decisions.md` D72 (+ D71 marked closed).
- `Worker.Classify` is mutex-serialized, so one shared worker is concurrency-safe;
  a worker POOL for the concurrent listener is an N1.2b follow-up, noted not hidden.
- NOT in scope (stated plainly): the real HTTP proxy listener + socket-backed
  FlowTable (N1.2b); TLS interception (N1.3). Respects D29/D35 (parser in the
  sandbox), D10/D29 (content-free projection), D17 (worker error is auditable).
