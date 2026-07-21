## Why

All enforcement today is POST-decision (D49): the engine classifies a file fully,
decides, records, then contains it (quarantine/encrypt) — the file was already opened.
That is containment, not prevention (D16), and it is the DLP product's biggest
credibility gap. True prevention means answering the fanotify PERMISSION event with DENY
before the open completes — but the accessing process blocks uninterruptibly in that
window (D18), so a full parse cannot run inside it. The two-tier answer: a CHEAP
synchronous tier decides within the permission budget while the FULL classification runs
asynchronously for audit + containment. This ships the synchronous tier's decision logic.

## What Changes

- `internal/agent/prefilter.PreFilter` (implements `watchdog.Evaluator`): the synchronous
  tier. It ALWAYS submits the full-file async job (tier 2), and produces an inline BLOCK
  ONLY for a high-confidence partial deny (tier 1, B3). Seams: `PartialDecider` (bounded
  classify→policy in the sandboxed worker, D13/D72) and `AsyncSubmitter` (the engine).

## Capabilities

### Added Capabilities
- `inline-prevention`: the two-tier prefilter that can answer a permission event with an
  inline BLOCK for cheaply-provable high-confidence hits, deferring everything else to
  asynchronous containment.

## Impact

- New `internal/agent/prefilter`; `docs/decisions.md` D94.
- Proven in plain Go (the watchdog seam needs no privilege): a high-confidence partial
  deny → VerdictBlock (and drives the REAL watchdog to a kernel Deny); a low-confidence
  hit → Allow (contain async, never block on a prefix guess); a clean partial → Allow; a
  decide error → fail-open + surfaced; the async full-file job is submitted on EVERY path.
- NOT in scope (stated, and EMPIRICALLY re-confirmed this session): the privileged
  permission-mode syscall wiring (B2) — `fanotify_init(FAN_CLASS_CONTENT)` needs
  CAP_SYS_ADMIN in the INIT user namespace; a `--privileged --userns=host` rootless
  podman container was tested and still returns EPERM (container-root maps to the
  unprivileged host user, D52), so the real FAN_OPEN_PERM path is external-gated to a host
  with genuine root. Also deferred: the fd-passing plumbing (privileged agent → engine
  reads the fd → worker parses a bounded prefix), the PartialDecider implementation, and a
  distinct `DENY_OPEN` verb if BLOCK's semantics prove insufficient (BLOCK suffices now).
  Respects D13 (the prefilter never parses — the worker does), D18 (the watchdog owns
  budget/self-PID/fail-open), D17 (fail open), D16 (inline never replaces the audit trail).
