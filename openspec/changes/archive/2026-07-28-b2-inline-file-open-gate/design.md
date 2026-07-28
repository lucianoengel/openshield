# Design

## The prefix comes from the kernel's descriptor, not from a fresh open

This is the load-bearing decision, and it resolves both defects at once.

A `FAN_OPEN_PERM` event arrives with an **open file descriptor** for the exact file being opened. The
agent reads a bounded prefix from that descriptor and sends the bytes over the IPC. The engine
classifies what it is given.

**No recursion, structurally.** No new `open()` happens anywhere, so no second permission event can be
raised, so the deadlock cannot occur. The alternative — exempting the engine's PID — would avoid the
deadlock by bookkeeping that can go stale: a restarted engine has a new PID, a reused PID exempts the
wrong process, and the failure mode of getting it wrong is an unrecoverable host. Deadlock-immunity by
construction beats deadlock-avoidance by maintenance, and this codebase already prefers that trade
elsewhere (composing an alert title from enum names to make a content leak *unexpressible* rather than
merely discouraged).

**No TOCTOU.** The descriptor refers to the inode the kernel is deciding about. Opening by path could
get a different file, and the gate would then authorize what it inspected while releasing what it did
not.

### What this costs, stated plainly

The privileged agent **holds** attacker-controlled bytes in a buffer and writes them to a socket.

D13 forbids the privileged process **parsing** attacker bytes, and this does not parse: it is a
bounded `read` into a fixed buffer and a `write` to a socket. No format is interpreted, no length
field is trusted, no allocation is sized by the content. The exec bridge is described as parser-free
and stays so under the same definition.

It is a real widening nonetheless — the agent now touches bytes it previously never saw — and it is
accepted deliberately, because the alternative is a PID table whose staleness bricks the machine.

## Scope, and why a mount is refused

The mark covers configured directories. Marking a mount routes **every** open on the host through a
permission window: the package manager's, the shell's, the engine's, the agent's own. Even with
fail-open that is a latency tax on every syscall, and any bug in the path becomes a system-wide hang.
The exec gate already learned this (D341's scope narrowing); this starts there rather than arriving
there.

## A second socket rather than a kind byte on the first

The exec wire carries `{ID, PID, Path}` and is VM-proven. A file-open question needs a prefix as well,
so the frames differ; and the two gates have different risk profiles — an operator may reasonably want
exec prevention without file-open prevention, whose availability cost is far higher.

Separate sockets make that independently configurable and leave a shipped protocol untouched. The cost
is one more setting, which is the cheaper mistake to make.

## Budget

The exec gate measured p50 41µs and p99 987µs against a 200ms window (D301). A file-open verdict adds
a bounded read and a prefix classification, so the budget is configurable and defaults conservatively.
The watchdog already answers ALLOW when it elapses; what this must not do is make the *common* case
slow, so the same measurement discipline applies before it is called done.

## Sequencing, because this is a gate that can hang a host

1. The wire and the producer, with unit tests, no kernel.
2. The agent side behind a setting that is off by default.
3. On the VM: a *self-contained* directory, one file, verify ALLOW first — the fail-open path — before
   any DENY is attempted.
4. Only then the DENY path, and the mutation that proves the gate is load-bearing.

Every VM command runs under `sudo -n timeout N`, because an unbounded root process in a permission
window is how this host was bricked twice already.
