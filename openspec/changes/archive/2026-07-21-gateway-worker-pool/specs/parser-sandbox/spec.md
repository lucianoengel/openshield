# parser-sandbox delta

## ADDED Requirements

### Requirement: A pool of sandboxed workers classifies concurrently
The system MUST provide a pool of worker processes that classifies requests concurrently, bounded by
the pool size, behind the same classify interface as a single worker. Each worker MUST still be an
isolated sandboxed process. A worker whose classify call errors MUST be discarded and replaced so its
unknown IPC state never serves a later request, while the error itself is still surfaced to the caller
(never reported as a clean result).

#### Scenario: Concurrent classifications all return correct results
- **WHEN** many classify calls run concurrently against a multi-worker pool, each with inline content
  containing a CPF
- **THEN** every call returns the CPF detector hit, with no data race in acquiring and releasing workers

#### Scenario: A worker that errors is replaced, not reused
- **WHEN** a pooled worker's classify call returns an error
- **THEN** that worker is discarded and a replacement takes its place in the pool, and the error is
  returned to the caller
