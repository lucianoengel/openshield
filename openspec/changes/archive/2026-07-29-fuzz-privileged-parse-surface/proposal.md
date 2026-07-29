# Fuzz what the privileged agent decodes

## Why

The whole privilege split exists because parsers are dangerous. The agent holds `CAP_SYS_ADMIN`, so
`scripts/check-agent-deps.sh` bans every parser package from its dependency graph — and yet the agent
still decodes bytes it did not produce, from the kernel and from an IPC peer, with hand-rolled code.
Those decoders have never been fuzzed.

Measured: the tree has **exactly one** fuzz target (`FuzzLoadRecordIndex`), **no** `testdata/fuzz`
corpus anywhere, and **no** `-fuzz` or `-fuzztime` token in the Makefile or either workflow.

### The roadmap's stated reason is wrong for this codebase, and inheriting it would be dishonest

The roadmap names this gap as *"fuzz the untrusted parsers (the D13 threat — ClamAV-CVE-class RCE)"*.
Go is memory-safe. The ClamAV CVE-2025-20260 class — a heap overflow in a PDF parser reaching remote
code execution — is ruled out by the language, not by testing for it. Repeating that justification
would be claiming a threat this code does not have.

What fuzzing does find here is three things:

- a **panic** — an index-out-of-range in a hand-rolled decoder,
- an **unbounded allocation** from a kernel- or peer-supplied length,
- **non-termination** — a decode loop that fails to advance.

In an ordinary process each is a crash or a hang. In *this* process each is a **host-wide availability
event**, because the agent answers blocking permission events: while it is dead or stuck, every process
that opens a watched file sits in an uninterruptible window until the watchdog budget fires, and the
gate fails open the whole time. The severity comes from what the process does, not from what the
language permits.

## What Changes

- Fuzz targets for the five decoders reachable from `cmd/openshield-agent`, all in-package because the
  kernel decoders are unexported.
- **The inotify record walk is extracted into a pure function.** It parses `struct inotify_event`,
  whose `name[]` field is an attacker-created filename, and today it is welded to a syscall read loop
  — untestable by any means. The refactor is part of this ticket, not a drive-by.
- Every target asserts **progress**, not merely absence of panic: a successful decode must return a
  strictly shorter remainder, and a failed one must stop. A decoder that returns its input unchanged is
  an infinite loop inside the privileged agent, and Go's fuzzer surfaces that only through its own hang
  timeout.
- Decoded lengths are asserted against their declared bounds, so an allocation blowup is a test failure
  rather than an OOM.
- A bounded `-fuzztime` smoke pass in CI's existing `invariants` job.

## Capabilities

### New Capabilities

*(none)*

### Modified Capabilities

- `agent-process-boundary`: adds requirements that the privileged process's decoders survive arbitrary
  input — terminate, stay within their declared bounds, and never panic — and that a discovered
  crashing input becomes a permanent regression seed.

## Impact

- Affected specs: `agent-process-boundary`
- Affected code: `internal/agent/execmon`, `internal/agent/openmon`, `internal/agent/openipc`,
  `internal/agent/execipc`; `.github/workflows`
- One production refactor (extracting the inotify walk). No behaviour change.
- No proto change, no migration, no new dependency — Go native fuzzing only.

## Honest expectation, and what actually happened

**The prediction was zero defects. It was wrong — three were found, all one bug.**

The prediction is left here rather than edited away, because being wrong in this direction is the
result. Reading the decoders was not enough: all three bound their declared length against the buffer
before slicing, and all three do so correctly *on the architecture the tests run on*.

The bug is `int(someUint32FromTheWire)`. On a 32-bit platform `int` is 32 bits, so `0xFFFFFFFF`
converts to **-1**, every "is this length past the ceiling?" check passes, and the slice that follows
panics. Sites:

| Site | Consequence on 32-bit | Found by |
| --- | --- | --- |
| `execmon.decodeMeta` | `buf[4294967295:]` → panic in the exec gate | `FuzzDecodeMeta` under `GOARCH=386` |
| `openmon.decodeMeta` | same, in the loop answering `FAN_OPEN_PERM` | `FuzzDecodeMeta` under `GOARCH=386` |
| `openipc.ReadRequest` | short allocation, then `body[:pathLen]` → panic | an **existing** test, run under `GOARCH=386` |
| the inotify record walk | `buf[16:15]` → panic | reading it while extracting it |

Two things follow, and neither is the thing the ticket set out to prove.

**The real finding is not three bugs, it is that the suite had never run on a 32-bit architecture** —
on a project whose agent compiles for `GOARCH=386` and `GOARCH=arm` today. `openipc.ReadRequest` was
already covered by a test named `TestADeclaredLengthBeyondTheBoundIsRefusedBeforeAllocating`, which is
precisely the property that fails. It passed on amd64 forever. So the durable fix is a CI step, not
four patches.

**Fuzzing alone would not have found all of it.** The inotify site came from reading the arithmetic
during the extraction; no amount of fuzzing on amd64 would have reported it, because on amd64 it is
correct. And one bound assertion in the new targets could not fail until a seed was added that carries
an over-ceiling body — every other seed declares a huge length and supplies no bytes, so the reader
errors before the assertion is reached. An assertion that cannot fail is decoration; the mutation is
what exposed that.

**Honest bound on severity:** none of these is reachable through a real kernel or a well-behaved peer,
which write real lengths. They are latent panics in privileged code, not live holes — and the decoders'
own comments promise they survive malformed input, which on two shipped architectures they did not.

After the fixes, seven targets ran ~380M executions with no crashers, so `testdata/fuzz/` is empty.
That is a real result and not a missing deliverable: the mechanism is in place for the first crasher
that appears.

## Deferred to increment 2, as a decision rather than an omission

The **unprivileged** parse surface: `classify.extractZipArchive`/`extractOOXML`/`extractPDF` (recursive
archive extraction in the sandboxed worker), `gateway.extractSNI` (a raw pre-handshake TLS ClientHello
off a TPROXY socket, unauthenticated), `classify.LoadDocumentIndex` and `LoadEDMIndex` (the two
structural twins of the one target that *is* fuzzed), `dns.ParseQuery`, `smtp.ParseSession`,
`cef.Parse`, and — the most interesting of them — `classify.LoadSignedRules`, whose outer envelope is
`proto.Unmarshal`'d **before** its signature is verified.

They are worth doing and they are a different argument: those processes are sandboxed or unprivileged,
so a crash there is a contained failure rather than a host-wide one. Ranking them below the privileged
five is a judgement about blast radius, not about input trustworthiness — several of them take bytes
that are *more* hostile than anything the agent sees.
