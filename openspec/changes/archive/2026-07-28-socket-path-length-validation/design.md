## Context

D324 fixed the TEST suite's exposure to the unix address limit. The product's exposure is the same and
unguarded: every socket setting is `KindOutputPath`, which checks the parent directory and nothing about
length.

The failure it produces is quiet in a specific and bad way. `applyExecIPC` validates the configuration,
starts the verdict server, logs `exec-verdict IPC ACTIVE`, and the listener then fails — so the operator
has a process that said the feature was on. The privileged gate, unable to reach a socket that was never
bound, degrades to its static path and fails open with an audit per exec, exactly as designed. Every
component behaves correctly; the deployment does not work; nothing names the cause.

## Decisions

### A new kind, reversing D321

D321 met this question and answered no: a socket kind would have behaved identically to
`KindOutputPath`, and a kind distinguished from another only by its name is noise in a schema that
drives a UI. That was right at the time.

It is wrong now, because the two kinds no longer behave the same. A behavioural difference is precisely
what earns a distinct kind, and the alternative — a length check inside `KindOutputPath` keyed on the
field's NAME ending in `_SOCKET` — puts a behavioural rule in a string comparison, where the next person
to add `OPENSHIELD_FOO_LISTENER` gets no bound and no warning.

Worth recording as a reversal rather than quietly doing it: the earlier reasoning was sound, its premise
changed, and a decision register that only ever accumulates is one nobody trusts to reflect the code.

### The RUNNING platform's limit, not the portable minimum

The tempting simplification is to validate against 104 everywhere, since it is the smallest limit across
supported platforms and gives one number in one message. It is wrong: a 106-byte socket path binds
correctly on Linux, and refusing it would be rejecting valid configuration on the platform the product
actually ships on.

Refusing what works is a worse failure than a message that differs by platform, because the operator has
no recourse — the value is correct and the product will not take it. So the constant lives behind build
tags: 108 on Linux, 104 elsewhere (macOS's limit, and the safe answer for anything unlisted).

### Where the check sits, and what it does NOT do

It is a configuration check, so it catches a path that is too long at startup and reports it against the
field. It does not and cannot catch every bind failure — permissions, a full filesystem, a stale socket
held by another process, an abstract-namespace address — and it should not try, because a configuration
layer that pretends to predict a syscall's outcome would fail the first time the two disagreed.

The line is: the length is knowable BEFORE binding, from the value alone. Everything else is the
listener's to report.

## Risks / Trade-offs

- **A deployment already running with an over-long path would now fail to start.** In practice such a
  deployment cannot be working — the socket never bound — so this converts a silent non-feature into a
  loud refusal. That is the right direction, and the message names the field and the fix.
- **Two kinds that differ only in a length bound may look like over-modelling.** The bound is the whole
  point; without it the kind is `KindOutputPath` and the check has to live somewhere worse.
- **The `_SOCKET` naming guard remains name-based.** That is appropriate for a guard whose job is to
  catch a MISDECLARED field — it cannot use the declaration it is checking — but it does mean a socket
  setting named without that suffix escapes it. Stated here rather than pretended away.
