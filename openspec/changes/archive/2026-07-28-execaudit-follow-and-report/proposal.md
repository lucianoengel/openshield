# The exec connector stops reading at end-of-file and says nothing

## Why

`OPENSHIELD_EXEC_AUDIT_LOG` is described as "auditd log the exec connector reads (HIPS-5c)". An
operator sets it to `/var/log/audit/audit.log`, and the engine logs:

> engine: exec connector ENABLED — process executions enter the pipeline (HIPS-5)

What actually happens: the engine `os.Open`s the path, the scanner's `for sc.Scan()` loop drains it,
reaches EOF, and returns `nil`. The goroutine exits. Every execution recorded **before** startup is
ingested; **no execution after startup is ever seen**. Nothing is logged when this happens, because
returning `nil` is a successful return.

So the HIPS exec source is a detector that reports itself enabled, processes a backlog once, and is
inert for the rest of the process's life. "No suspicious executions" and "no executions were looked
at" read identically — which is D31's silent gap on the endpoint's process-visibility source.

The engine's own comment names the intended sources — "a tailed audit log, a fifo, or the audit
socket" — so the deployment shape was understood. The setting's description does not say it, and the
code does not enforce it.

## What Changes

- The exec source **follows** a regular file: on reaching the end it waits and resumes from where it
  stopped, so executions appended after startup enter the pipeline. It handles the file being
  truncated or replaced, which is what log rotation does to it.
- When the source **ends** — a fifo whose writer closed, a stream that will produce nothing more —
  the engine says so at WARN, naming that no further executions will be seen. An exec source that
  stops is a loss of endpoint visibility and must not be a silent one.
- The startup line reports which mode it is in, so "following" and "read once" are distinguishable
  before an incident rather than during one.

## Impact

- Affected specs: `execaudit-connector`
- Affected code: `internal/connectors/execaudit`, `cmd/openshield-engine`
- No proto change, no migration, no new dependency.
- Observe-only is unchanged (D1). This changes how much the connector SEES, not what it does with it.
- A deployment already piping `tail -F` into a fifo is unaffected: a fifo is not a regular file and
  keeps its current behaviour, plus the new end-of-source warning.

## Honest limits

- **Following is polling, not inotify.** A poll interval means a bounded delay between an exec being
  written and being classified. For an observe-only source that is acceptable; it is stated rather
  than hidden, because the delay matters if someone later builds a response on top of it.
- **Rotation is handled by reopening, and a rotation can still lose records** — anything written to
  the old file between the last read and the rename. Bounded by the poll interval and named here, not
  claimed away.
- **This does not make the connector a live exec gate.** Inline exec prevention is HIPS-3, over
  `FAN_OPEN_EXEC_PERM`, and is a different and already-shipped path. This source is for visibility and
  post-hoc detection.
