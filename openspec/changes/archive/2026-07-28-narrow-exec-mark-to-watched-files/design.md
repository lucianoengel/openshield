## Context

Three mark shapes, measured on kernel 6.8 rather than read from a man page — the mount mark exists
because a narrower one was tried and did not deliver (D224), and that history is exactly why this is
measured again:

| mark | direct child | nested | outside |
|---|---|---|---|
| mount | delivered | delivered | not delivered |
| directory + `FAN_EVENT_ON_CHILD` | **EINVAL** | — | — |
| per-file | delivered | not delivered | not delivered |

The `outside` column is worth reading carefully: it is `not delivered` for the mount mark too, because
the probe ran under `/tmp`, which is **tmpfs — a different mount from `/`**. That is also why D330's
damage varied with location: a monitored directory under `/opt` or `/usr/local/bin` marks `/` and takes
`sudo` and `bash` with it, while one under `/tmp` marks only tmpfs. The blast radius was a function of
where the operator pointed it, which is worse than a constant one because it is untestable by accident.

## Decisions

### Match the mark to the semantics, not to a preference for narrowness

Per-file marking can only MISS things; the mount mark can only WASTE. Those are not symmetric risks in a
security control, so narrowness is applied only where the scope is already defined and defended:

- **allowlist → per-file.** D330 bounded the default-deny to the monitored directories, so an execution
  outside them is out of scope by definition and generating an event for it is pure cost.
- **deny-list, behavioural floor, pipeline verdict → mount.** A deny-list names binaries to refuse
  wherever they run from; narrowing it silently reduces what it catches, which is the failure mode that
  is hard to notice and easy to ship.

A deployment configuring BOTH keeps the mount mark. Correctness first: the union of the two semantics is
global.

### `FAN_EVENT_ON_CHILD` would have been better and is not available

One mark per directory, new files covered by the kernel, no enumeration and no watcher. The kernel
returns EINVAL for it with `FAN_OPEN_EXEC_PERM`. This is the second time that has been discovered, so it
is now a test that prints the result rather than a comment that can be doubted.

### The new-file hole is the whole risk of this change

Per-file marks cover what existed when they were applied. Under default-deny an unmarked binary produces
no event and therefore RUNS — so a narrowing done naively converts an efficiency win into a bypass, and
a better one than an attacker could hope for: drop a binary into the watched directory and it is not
merely allowed, it is invisible.

Closed with an inotify watch marking on create, move-in and close-after-write. The residual race is real
— a binary created and executed before the watcher's mark lands escapes — and is documented rather than
hidden. It is a much smaller window than the alternative and, unlike the alternative, it is bounded by
scheduler latency instead of by an operator noticing.

## Risks / Trade-offs

- **A coverage regression is the failure mode.** Mitigated by scope (only where D330 already bounded it),
  by the inotify path, and by a VM scenario that creates a binary AFTER the agent starts and asserts it
  is still refused — the assertion that would catch the bypass.
- **More moving parts in the privileged binary.** The watcher adds inotify handling to a process that
  must remain parser-free; inotify is a fixed-shape kernel struct, not a parser, and the existing
  dependency rules already cover it.
- **Nested directories are not covered by a per-file mark** (measured above). Enumeration therefore
  walks the tree, and the watcher must watch each directory it finds.
