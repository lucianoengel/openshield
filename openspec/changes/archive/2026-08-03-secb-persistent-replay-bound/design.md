# Design — SEC-B persistent replay bound

## Why persist EXACTLY, and not the publisher's reservation scheme

`natsx.FileSeqStore` is reused, and its interface is satisfied unchanged, but its *usage* is
deliberately different. A publisher reserves a block of sequences ahead so the file is written once
per hundred messages; a crash then loses reserved-but-unused numbers, which appear downstream as a
counted gap and never as a replay.

A consumer cannot reserve ahead. A bound written above what has actually been applied refuses
legitimate controls, and the failure is silent — the host looks healthy and simply cannot be told to
stop enforcing. So the consumer writes the exact applied sequence, synchronously, on every accepted
control. That is affordable precisely because this channel is rare: a handful of controls over a
deployment's life, against a hundred telemetry messages a second.

## Why persist BEFORE applying

The two orders fail in opposite directions and one of them is the bug this change exists to fix.

- **Apply, then persist:** a crash in between restores a bound BELOW a control that already ran. The
  captured control replays on the next boot — which is exactly the defect, reintroduced inside the fix.
- **Persist, then apply:** a crash in between loses the control. The host stays ENFORCING, and the
  control plane can re-issue at a higher sequence.

The second is the direction this channel already commits to everywhere else ("anything unverifiable,
replayed, expired or of an unknown version changes nothing at all"). A write failure is treated the
same way — the control is refused, not applied-and-hoped.

## Why a corrupt bound stops the process but an unwritable one may not

They fail the same way at a glance and must not be treated the same.

An **unwritable** bound is a deployment shape: a read-only root, a `ProtectSystem=strict` unit, a
container with no writable `/var/lib`. Refusing to start there would turn this fix into a regression
for hosts that had no bound to lose in the first place. So on a path the operator never chose, the
binaries fall back to an in-memory bound and say so, loudly, at startup.

A **corrupt** bound means a bound existed and can no longer be read. Continuing from zero is precisely
what an attacker holding captured controls wants, and a bound that resets whenever the file is damaged
is a bound anyone with write access to the file can remove. That is a reason to stop.

Distinguishing them needs a typed error (`ErrBoundUnwritable`) and a caller that knows whether the
operator chose the path — hence `LookupEnv` rather than the `env()` helper, which cannot tell "unset"
from "deliberately empty". The same distinction is already the codebase's rule for paths
(`TestAnExplicitlySetBadPathStillFails`: a bad default is an unconfigured feature, a bad explicit
value is a typo worth failing the boot over).

## Why the shared-file guard is a startup error rather than a warning

The failure it prevents is silent and close to undiagnosable. The two files hold the same type and
opposite meanings; the telemetry high-water advances every hundred published messages, so a shared
file puts the replay bound in the thousands within seconds of boot. From then on every legitimate
control is refused as a replay, with a message about replay that is technically accurate and points
nowhere near the cause. Nothing else about the host looks wrong.

Absolute paths are compared rather than strings, because an operator writing one path relative and one
absolute is not doing anything unusual.

## Two defects found by trying to prove this end to end

Both are recorded here rather than folded silently into the fix, because each was invisible to unit
tests for a different structural reason.

**An anchored, empty ledger could not be reopened.** `prepareForWriting` branched on the *epoch* count
to decide whether the database was fresh, but `resumeTail` requires at least one *entry*. Between
opening the ledger (which persists the anchor epoch) and the first decision (which may never come),
the database holds an epoch and no entries — and reopening in that state failed with "ledger:
unavailable: no rows in result set" and the binary exited. Permanently: every subsequent start hit the
same branch, so the process could never write the entry that would have let it start. `entryCount` was
already being read and never used, which is the shape of a branch that was meant to be there.

Unit tests missed it because they append before closing; only a scenario that starts a process,
records nothing, and restarts it can reach the state — which is what a host disabled fleet-wide before
it decided anything does.

**The gateway's degraded counters were reported only in access mode.** The reporter sat inside
`runAccessMode`, which is an ALTERNATIVE to the ordinary proxy path rather than a stage of it — `main`
returns straight after calling it. So a gateway doing the thing gateways mostly do reported neither a
suppressed enforcement, nor a dropped audit append, nor a fleet-control forgery flood.

The block carried a comment explaining it had been deliberately hoisted out of the NATS conditional
because "a gateway deployed without NATS still enforces … and would have reported none of it. That is
the same defect this whole thread is about, reintroduced one commit after fixing it." The hoist was
right and one scope short: the identical argument applies to the mode. It is now a function taking the
mode-specific counters as arguments, so the next caller is handed the common set rather than having to
remember to copy it.

## Testing notes

The integration scenario asserts on both sides of the bound in one run, and the second half is not
decoration. "The restarted gateway did not disable" has two explanations — the bound refused the
replay, or the message never arrived — and a subscriber that silently stopped receiving would produce
an identical, passing test.

So the scenario adds two independent controls:

- an **in-memory gateway**, given the identical captured bytes, which must disable — proving the
  ammunition is live rather than expired, mis-addressed or unsigned;
- a **freshly-issued control** at a higher sequence, which the restarted gateway must apply — proving
  the channel still delivers to that process, and covering the failure this fix could plausibly
  introduce and which would be worse than the bug: a bound that leaves a host unable to be stopped.

The "and it was counted" assertion is made only after the fresh control has been applied, because the
degraded reporter fires on movement — a rejection alone can sit unreported until something else moves.
That ordering is what turned an unexplained timeout into the discovery of the reporter's mode scoping.
