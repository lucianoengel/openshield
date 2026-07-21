## Why

`privileged.Worker.Classify` holds a mutex — one request in flight at a time. The
gateway's HTTP proxy (D73) is concurrent (many flows at once), so every body
classification serializes through a single worker: correct, but a throughput
bottleneck. This gives the gateway a POOL of sandboxed workers so concurrent flows
classify in parallel.

## What Changes

- `internal/agent/privileged.Pool` — N worker processes behind the SAME
  `Classify(ctx, *ClassifyRequest) (*ClassifyResponse, error)` method the single
  Worker exposes (so it satisfies the gateway's/engine's classifier interface
  unchanged). `StartPool` spawns the workers; `Classify` acquires an idle worker
  from a buffered channel (the channel is the semaphore — backpressure when all
  busy, honours ctx cancellation), classifies, and releases it.
- On ANY `Classify` error the worker's framed-IPC state is unknown (a timeout
  desyncs the protocol, a crash kills it), so the pool DISCARDS that worker and
  spawns a REPLACEMENT — a poisoned worker never stays in rotation; if replacement
  fails, the old handle is returned so the slot is not lost (rather than
  deadlocking the pool). `Close` drains and closes idle workers.
- `cmd/openshield-gateway`: `OPENSHIELD_WORKER_POOL` (default 4); `StartPool`
  instead of a single `StartWorker`; the pool is passed to `gateway.New`.

## Capabilities

### Modified Capabilities
- `parser-sandbox`: a POOL of sandboxed workers classifies concurrently; each
  worker is still the seccomp/no-network sandbox (D29/D35).
- `network-gateway`: the gateway classifies concurrent flows across a worker pool
  rather than serializing through one worker.

## Impact

- New `internal/agent/privileged.Pool`; `cmd/openshield-gateway` wiring;
  `docs/decisions.md` D76. The single Worker and the classifier interface are
  unchanged (the engine keeps using one worker; the pool is the gateway's answer).
- Proven with the REAL worker binary under `-race`: a size-4 pool handles many
  concurrent inline-Content classifications, every one returning the CPF hit; a
  size-1 pool still works; Close closes the workers.
- NOT in scope (stated): dynamic pool resizing; per-worker health checks beyond
  replace-on-error; sharing one pool across the engine and gateway processes.
  Respects D29/D35, D72, D17 (a worker error is surfaced AND the worker replaced).
