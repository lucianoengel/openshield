# B2: answer a file-open permission event inline

## Why

`internal/agent/prefilter` is the synchronous tier of two-tier inline prevention. It implements
`watchdog.Evaluator`, decides from a size-bounded prefix classified in the sandboxed worker, and hands
the full event to the async tier. It is complete and tested, and **nothing produces the events it
exists to answer.** The README states this honestly today: inline blocking of a file open "remains
designed and not wired".

Everything above it already ships. The watchdog owns the budget, the self-PID exemption and fail-open
(D18). The exec gate proves the shape end to end on a live kernel: a privileged producer, a
parser-free IPC bridge, a verdict from the engine's full pipeline (D244). What is missing is the
`FAN_OPEN_PERM` producer and the wiring that carries a file-open question across the same seam.

## Two defects in the design as drafted, found by reading it before building it

**The engine opening the file would deadlock the host.** `Decider.DecidePartial` opens `e.Path` to
read its prefix. If that open falls under the mark, it raises another permission event, which the
agent asks the engine to answer, which opens the file again. Both processes then wait on each other
inside a window that is **uninterruptible** — the machine does not recover. The watchdog exempts only
`SelfPID`, the agent's own, which does not help here because the opener is a different process.

**Opening by path is a TOCTOU hole.** The permission event names an inode; the engine opening by path
may get a different file, because anything may replace the path between the event and the open. The
gate would then authorize the file it inspected while the kernel releases the file it did not. That is
a correctness bug independent of the deadlock, and it exists in the drafted design regardless of how
the recursion is solved.

## What Changes

- A `FAN_OPEN_PERM` producer in the privileged agent, scoped to configured directories — never a
  mount.
- **The agent reads the bounded prefix from the fanotify descriptor the kernel already handed it**,
  and sends those bytes across the IPC. The engine does not open anything.
- A second IPC socket for open-permission questions, distinct from the exec one, so the two gates are
  independently enable-able.
- The engine answers using the existing prefilter, unchanged.

## Impact

- Affected specs: `inline-prevention`
- Affected code: `internal/agent` (producer, IPC), `cmd/openshield-agent`, `cmd/openshield-engine`,
  `internal/config`
- No proto change. No migration.
- Root-gated and off by default. A deployment that does not configure it is bit-for-bit unaffected.

## Honest limits

- **Fail-open, always.** The budget elapsing, the engine being unreachable, the IPC erroring, the
  classifier failing — every one answers ALLOW and audits at high severity (D17/D18). A file-open gate
  that failed closed would hang every process on the host.
- **Prefix-only.** A verdict comes from a bounded prefix, so content past the ceiling is not seen
  inline. The async tier classifies the whole file and contains it afterwards; inline is friction,
  not a guarantee (D16).
- **Directory-scoped.** Marking a mount would put every open on the host — including the package
  manager's, the shell's, the engine's own — through a permission window. That is not a configuration
  this should accept.
