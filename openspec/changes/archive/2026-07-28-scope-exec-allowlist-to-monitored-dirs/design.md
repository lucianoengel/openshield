## Context

Found by writing the first integration test for `OPENSHIELD_EXEC_ALLOW` and running it on the rooted VM.
The test asserted the obvious pair — an allowlisted binary runs, an unlisted one does not — and the
allowlisted binary was refused. The investigation that followed bricked the VM twice and needed an
out-of-band reboot, which is itself the clearest statement of the defect.

Three facts, each measured rather than reasoned:

| | |
|---|---|
| deny-list by full path, same directory | works (control) |
| allowlist matching in isolation (unit) | correct — listed allows, unlisted blocks, unresolved allows |
| allowlist on a live kernel | refuses `sudo`, `cat`, `/bin/bash`, and sshd's login shell |

So the matcher is right and the SCOPE is wrong. `execmon.Open` marks with `FAN_MARK_MOUNT` because a
directory inode mark does not deliver `FAN_OPEN_EXEC_PERM` for files executed inside it — the comment
saying the mark "is broader than the named path" has been there since the feature was written. Nothing
carried the narrowing forward to the decision.

## Decisions

### Scope the default-deny, not the mark

The apparent fix is to narrow the kernel mark. It is not available: the mount mark is what makes exec
permission events arrive at all, which is the constraint the original comment records. Per-file marks
would mean marking every executable under the directory and re-marking on every create — a directory
watch reimplemented in fanotify, racing the thing it watches.

So the mark stays broad and the DECISION narrows: an exec outside every monitored directory is out of
scope and allowed. The agent already has the directory list; it simply never reached the evaluator.

### The deny-list stays unscoped, deliberately

Symmetry would be easier to explain and would be wrong. A deny-list's blast radius is exactly what it
names, so breadth costs nothing and helps: an operator naming `/usr/bin/nc` means it, wherever it is
executed from. A default-deny's blast radius is *everything else*, which is only meaningful inside a
declared boundary.

Narrowing the deny-list would also silently weaken existing deployments — the opposite failure from the
one being fixed, and harder to notice.

### What this does not fix

The agent still receives an event for every execution on the mount and answers it. The waste is real
(a permission round-trip per exec, host-wide) and is not addressed here; what is addressed is that the
answer is now correct. Narrowing the mark itself is a separate piece of work with its own kernel-level
risks, and pretending otherwise would be how a scope fix turns into a rewrite.

## Risks / Trade-offs

- **This narrows a security control.** An operator who believed default-deny covered the whole host
  loses that — but they never had it in a usable form, because enabling it made the host unusable.
- **The scope check is a path-prefix test**, so a symlink into a monitored directory is judged by its
  resolved path. That is the correct reading (the kernel reports the resolved path) and is stated in the
  test rather than left to inference.
