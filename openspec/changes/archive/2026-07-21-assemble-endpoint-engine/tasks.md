## 1. The engine

- [x] 1.1 `internal/engine`: `classifyStage` bridging `privileged.Worker` → `State.Classification`
      (type+confidence+count, EMPTY matched_text — no content crosses, D29); a worker error is a
      stage error
- [x] 1.2 `engine.New(worker, policyStage, ledger, logger)` → dispatcher (classify, policy) + audit
      sink + logger; `Process(ctx, event) (*Decision, error)`
- [x] 1.3 `cmd/openshield-engine`: start worker, open ledger (signer via write-resume file, D46),
      assemble engine, process events

## 2. Tests

- [x] 2.1 **Test** (real worker binary + real Postgres): a seeded-CPF file event → ALERT decision →
      verifiable ledger entry. `TestWalkingSkeleton`
- [x] 2.2 **Test**: the built classification carries no matched text (content-free). `TestNoContentInPipeline`
- [x] 2.3 **Test**: a worker error terminates as a logged/recorded failure, not a clean result.
      `TestWorkerErrorIsAuditable`

## 3. Split preserved + docs

- [x] 3.1 Confirm `check-agent-deps` still passes (the privileged agent gains no OPA/parser); the
      engine holds OPA+pgx and is unprivileged
- [x] 3.2 Note in `docs/decisions.md` (new D-number): the three-process shape and why; the logger
      seam closed
- [x] 3.3 Validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| classify stage carries matched text | `TestNoContentInPipeline` |
| worker error swallowed as empty result | `TestWorkerErrorIsAuditable` |

The walking skeleton runs end to end against the REAL worker binary + REAL
Postgres: a file with a seeded CPF (111.444.777-35) → the worker classifies →
policy ALERTs → the decision is recorded → the ledger verifies
(`TestWalkingSkeleton`, live output: "CPF file → ALERT → verifiable ledger
entries=1"). The classification built from worker hits carries no matched text
(D29); a worker error terminates as a logged/recorded failure, not silence.
`check-agent-deps` still passes — the privileged agent gains no OPA/parser; the
engine (the only holder of both OPA and pgx) is unprivileged. Docs: D48.
