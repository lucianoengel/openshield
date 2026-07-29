# B2: a gated open should be fully classified, not only prefix-deep

## Why

The file-open gate decides from a bounded prefix (D352) and records that decision as evidence (D358).
It never classifies the file any further. Meanwhile the design and the README describe a second tier
that classifies the WHOLE file and contains it (D16) — `prefilter.PreFilter` even has an
`AsyncSubmitter` seam for exactly that, and it is not wired.

So the inline half is friction, as intended, and the half that was supposed to make it more than
friction does not exist. Content past the prefix ceiling is neither refused inline nor detected after.

## Why it was not simply wired

Naively submitting the event recurses, and the recursion is not a lock cycle but a feedback loop: the
async classification opens the file, that open falls under the fanotify mark, the gate must answer it,
and answering submits async again — forever.

Worse, the process that opens is not the one on the other end of the socket.
`internal/agent/worker/worker.go` does `os.Open` on a `ClassifyRequest_Path`, so it is the sandboxed
WORKER that touches the file, not the engine.

## What Changes

- The engine runs a **dedicated worker pool for gate verdicts**, separate from the classification pool
  D357 sized. One extra sandboxed process, so a nested gate decision can never be starved by the async
  work that triggered it.
- After answering, the engine **submits the event to the async tier**, so the whole file is classified,
  recorded and contained by the normal pipeline.
- The cycle is broken by **path dedupe**: submitting async for a path suppresses further submissions
  for that path within a short TTL. The async classification's own open still produces a gate decision
  — it is answered, just not resubmitted — so the loop terminates after one iteration.

## Impact

- Affected specs: `inline-prevention`
- Affected code: `cmd/openshield-engine`, `internal/agent/prefilter`
- No proto change, no migration, no new dependency.
- Fail-open semantics are unchanged. Every failure path still allows.
- Off unless the gate is configured.

## Honest limits

- **A repeat open within the TTL gets a fresh VERDICT but not a fresh async classification.** The gate
  still decides every open; only the re-classification is suppressed, and the file has not changed in
  between.
- **An extra gate round trip per async classification** (~6ms at the default prefix). Real, and it
  belongs in the runbook beside the existing prefix-size guidance.
- **One more sandboxed process.** That is the price of the nested decision never being starved, and it
  is cheaper than the alternative failure, which is the gate silently failing open under load.
