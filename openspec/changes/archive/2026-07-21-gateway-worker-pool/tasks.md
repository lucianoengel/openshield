# Tasks — gateway worker pool (D76)

## 1. Pool (internal/agent/privileged.Pool)

- [x] 1.1 `Pool` with an `idle chan *Worker` (the semaphore), stored ctx/path/args for replacement. `StartPool(ctx, path, size, args...)` spawns `size` workers (min 1) into the idle channel; on a spawn failure it closes what it started and returns the error.
- [x] 1.2 `Classify(ctx, req)`: acquire from `idle` (select on `ctx.Done()`), classify, and on success release. On ANY error: `Close` the worker, spawn a replacement (return it to idle), else return the old handle; return the error to the caller regardless (D17).
- [x] 1.3 `Close()`: drain and close idle workers (idempotent); release closes rather than parks after Close.

## 2. Binary

- [x] 2.1 `cmd/openshield-gateway`: `OPENSHIELD_WORKER_POOL` (default 4); `StartPool` instead of `StartWorker`; pass the pool to `gateway.New` (it satisfies the classifier interface).

## 3. Proof (guards, each mutation-tested)

- [x] 3.1 **Test**: build the REAL worker binary; `StartPool(size 4)`; fire 40 concurrent `Classify` calls with an inline-Content CPF body; assert EVERY call returns exactly the CPF hit (bounded so a broken release fails cleanly). Run under `-race`.
- [x] 3.2 **Test**: a size-1 pool classifies correctly (degenerate case).
- [x] 3.3 **Test**: after `Close`, a Classify with a cancelled context returns promptly (bounded) rather than hanging.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D76: the gateway classifies concurrent flows across a worker pool; a channel-semaphore bounds in-flight parses; a worker that errors is replaced so its unknown IPC state never poisons the pool; the single mutex-serialized worker stays correct for the engine.
- [ ] 4.2 `openspec validate gateway-worker-pool --strict`; `make all` + `-race`; doccheck; archive via the skill; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| release drops the worker instead of returning it to idle | `TestPoolConcurrentClassify` (deadlock, bounded) |
| acquire ignores `ctx.Done()` | `TestPoolCloseIsBounded` (cancelled-acquire hang, bounded) |

NOTE: the replace-on-error path is defensive robustness; it is not directly unit-tested (inducing a
real worker IPC failure needs process-kill machinery out of scope here) — recorded honestly rather than
claimed as covered.

THE VERDICT (D76): the gateway classifies concurrent flows across a pool of N sandboxed workers, a
channel-semaphore bounding in-flight parses; an errored worker is discarded and replaced so its unknown
IPC state never poisons the pool; the single mutex-serialized worker stays correct for the engine.
Proven with the real worker binary under -race. NOT in scope: dynamic resizing; health checks beyond
replace-on-error; a shared cross-process pool.
