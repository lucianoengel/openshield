# Tasks — worker-classify network bodies (close D71)

## 1. Proto: inline-content classify subject

- [x] 1.1 `proto/openshield/v1/ipc.proto`: add `bytes content = 6;` to `ClassifyRequest.oneof subject` (beside `path`, `file_handle`), documenting that a network-capable caller that already holds the body hands bytes to the worker so the PARSER runs in the sandbox — the path-only invariant is the AGENT's discipline, not the proto's.
- [x] 1.2 `make proto`; `proto-check` clean.

## 2. Worker: handle the content variant

- [x] 2.1 `internal/agent/worker.Handle`: switch on the subject. Content → classify `bytes.NewReader(content)` through the SAME `limitReader` (max_bytes ceiling, truncated flag) and Classifier as the path case; Path → unchanged; no subject → error. Empty content is a valid no-hit input (distinguished from no-subject by the oneof type).

## 3. Gateway: classify via the worker

- [x] 3.1 `internal/gateway`: replace the `*classify.Classifier` field with the private `classifier` interface (`Classify(ctx, *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error)`) — the same one the engine uses. Remove the `internal/classify` import.
- [x] 3.2 Body-classify stage: build `ClassifyRequest{RequestId/EventId: eventID, Subject: Content{body}, MaxBytes: …}`, call the classifier, surface `resp.Error` as a stage failure (D17), build the content-free `LocalClassification` from `resp.Hits` (type+confidence+count, matched text empty, D10/D29).
- [x] 3.3 `New(classifier, policy, ledger, logger, deadline)` takes the interface; add `NewFromWorker(*privileged.Worker, …)` production constructor, mirroring `engine.NewFromWorker`.

## 4. Proof (guards, each mutation-tested)

- [x] 4.1 **Test**: a gateway walking-skeleton builds + starts the REAL `openshield-worker` binary and a fake in-memory ledger (no Postgres), sends a Request whose Body carries a CPF via Content, and asserts an audited ALERT — the body was classified IN THE WORKER.
- [x] 4.2 **Test**: fast assembly tests use a `fakeWorker` returning hits — BLOCK/REDIRECT routing to the flow enforcer, observe-only default, content-free projection (matched text empty) — preserved from D70; plus a guard that the gateway sends inline Content (never a path).
- [x] 4.3 **Test**: `worker.Handle` content variant classifies inline bytes (CPF hit); empty content → no hits, no error; content over max_bytes → truncated; no subject → error.
- [x] 4.4 **Test**: a dependency-graph guard asserts `internal/gateway`'s deps do NOT include `internal/classify` — the network process must not link the parser (the `check-agent-deps` discipline applied to the gateway).

## 5. Docs, ship

- [x] 5.1 `docs/decisions.md`: D72 (gateway body classification runs in the worker — D71 closed; the network-capable process holds bytes but never runs the parser; the worker gains an inline-content classify path shared with the endpoint's file path, bounded identically). Mark D71 closed-by-D72.
- [ ] 5.2 `openspec validate worker-classify-network-bodies --strict`; `make all` + `-race`; doccheck; archive via the skill; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| gateway sends `Path` instead of inline `Content` | `TestGatewayClassifiesBodyAsInlineContent` (+ real-worker skeleton) |
| gateway ignores `resp.Error` from the worker | `TestWorkerErrorIsAFailure` |
| `internal/gateway` links `internal/classify` (parser in the network process) | `TestGatewayDoesNotLinkTheParser` |
| worker content case ignores the supplied bytes | `TestHandleClassifiesInlineContent` |

THE VERDICT (D72): the gateway body is now parsed IN THE SANDBOXED WORKER via a new
`ClassifyRequest.content` inline-bytes subject, bounded identically to the file path; the
gateway depends on the classifier interface and no longer links `internal/classify` (deps
guard); a real-worker walking-skeleton proves a CPF body → audited ALERT with the parse in the
worker. D71 CLOSED. NOT in scope (stated): the real HTTP proxy listener + socket-backed
FlowTable (N1.2b); TLS interception (N1.3).
