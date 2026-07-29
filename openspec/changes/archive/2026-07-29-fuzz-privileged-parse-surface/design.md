# Design

## Context

`go list -deps ./cmd/openshield-agent` returns eight openshield packages: `agent/execipc`,
`agent/execmon`, `agent/openipc`, `agent/openmon`, `agent/watchdog`, `behavioral`, `config`. That list
*is* the privileged attack surface, and two survey findings about it are worth recording because both
contradict what one would assume from reading the connector layer.

**`connectors/fanotify.ParseEvent` is not in the privileged binary.** It links only into the
unprivileged engine. The agent carries its own, duplicated, unexported decoders of the same kernel
struct: `execmon.decodeMeta` (using `encoding/binary`) and `openmon.decodeMeta` (hand-rolled shifts).
Anyone looking for "the agent's fanotify parser" in `connectors/` finds the wrong code — and would fuzz
a function that never runs privileged.

The duplication is itself worth noting: three decoders of `fanotify_event_metadata` exist, and they do
not agree. `execmon`'s reads `Mask`; `openmon`'s does not (it does not need it, but the divergence is
invisible from either site).

**The IPC direction is already asymmetric and correct.** The agent is the *client* on both sockets, so
the privileged side decodes only `ReadResponse` — fixed width, no peer-supplied length, so there is
nothing to allocate from. The length-bearing `ReadRequest` on both protocols is decoded by the
unprivileged engine. This is a design strength to state, not a gap to close; the openipc package doc
already argues it. Fuzzing both directions is still right, but they should not be ranked as equals.

## Goals / Non-Goals

**Goals:**

- Fuzz every decoder reachable from the privileged binary.
- Assert the property whose violation wedges a host — termination — not merely absence of panic.
- Make the inotify record walk testable at all.
- Establish the corpus mechanism, so a crasher found in five years is a permanent regression test.

**Non-Goals:**

- Finding a bug. If there is one it will be found; the ticket is not justified by expecting one.
- A soak. CI gets a smoke budget; real fuzzing runs locally and on demand.
- The unprivileged parse surface (increment 2 — see the proposal).
- Changing any decoder's behaviour. The inotify extraction is a pure refactor; if fuzzing finds a
  defect, fixing it is a separate change with its own reasoning.

## Decisions

### The assertion is progress, not "does not panic"

Go's fuzzer gives absence-of-panic for free — any target body at all gets it. That is the weak half of
what these decoders must guarantee.

The strong half is that a streaming decoder **advances**. `decodeMeta` returns `(m, rest, ok)` and its
caller loops on `rest`. If some input made it return `ok == true` with `rest` no shorter than `buf`,
the agent spins forever in a goroutine that is supposed to be answering permission events — and the
kernel is holding processes the whole time. Go detects that only through its hang timeout, which
reports a stuck worker rather than a malformed frame, so the diagnosis is slow and confusing at exactly
the moment it matters.

So every target asserts `len(rest) < len(input)` on success, and `rest` unused on failure. This turns a
class of infinite loop into an ordinary test failure with the offending bytes attached.

*Alternative considered:* rely on the fuzzer's hang detection. Rejected — it reports the symptom in the
wrong vocabulary, and only after the default ten-second timeout, and only if the loop is tight enough
to trip it.

### The inotify walk is extracted, not fuzzed in place

`WatchForNewExecutables` interleaves the record walk with `unix.Read`, `os.Stat`, `MarkFile` and a
watch-descriptor map. There is no way to reach the parse without a real inotify fd and a real
filesystem — which is why it has no test today, of any kind.

Extracting the walk into a pure `[]byte → []record` function makes it fuzzable and makes the syscall
loop read as what it is. The extraction is deliberately *pure*: the `os.Stat`/`MarkFile` half stays
where it is, because moving side effects is a different change with a different risk.

*Alternative considered:* fuzz through the public `WatchForNewExecutables`. Rejected — a fuzz target
that needs a kernel fd is a fuzz target that runs nowhere, including CI.

### CI gets a smoke budget, and the corpus does the real work

A bounded `-fuzztime` pass in the existing `invariants` job (1m20s against a 5m48s workflow) catches an
obviously-broken decoder on a change that introduces one. **It is not a soak**, and the tasks say so
rather than letting a green check imply more than it proves: a ten-second run explores a tiny fraction
of the input space, and finding nothing in it is close to no evidence.

The durable mechanism is separate and is the actual point. `go test` replays a fuzz target's seed
corpus — `f.Add` cases plus everything under `testdata/fuzz/<Target>/` — on **every ordinary run**, with
no `-fuzz` flag. So a crasher found during a long local run, or by someone in a year, is committed as a
file and checked forever at zero cost. That property is what makes fuzzing worth wiring in even when the
scheduled budget is small.

*Alternative considered:* a nightly long-running fuzz job. Reasonable and deferred — it needs somewhere
to persist a growing corpus between runs, which is an infrastructure decision, not a test one.

### Seeds are chosen to be structurally interesting, not random

A fuzzer starting from `[]byte{}` spends its budget rediscovering the header length. Seeds include: an
exactly-`metaLen` buffer; a valid frame; a frame declaring `EventLen` of zero, of `metaLen-1`, of
exactly `len(buf)`, and of `MaxUint32`; and two concatenated frames, so the *loop* is exercised and not
only a single decode. The `EventLen == 0` and `MaxUint32` cases are the two that would produce
non-termination and a huge slice bound respectively, so they are seeded rather than left to chance.

## Risks / Trade-offs

- **The ticket may find nothing, and a reader may conclude it was wasted.** → Stated up front in the
  proposal, and the three non-bug justifications are stated with it. The decision record will report a
  null result as a null result.
- **A smoke-budget fuzz pass in CI could read as stronger assurance than it is.** → The workflow step
  and the tasks both say it is a smoke test. The claim the project makes publicly must match.
- **Fuzzing is nondeterministic, so a CI fuzz step can fail on a commit that did not cause it.** → The
  budget is small and the corpus replay (which *is* deterministic) is what runs on every test. A
  genuinely flaky discovery is a real finding: it gets committed as a seed, at which point it stops
  being flaky.
- **The inotify extraction touches privileged code to enable a test.** → Pure refactor, no behaviour
  change, and the existing package tests plus the VM suite cover the surrounding loop. Worth naming
  because "changed the privileged agent to make it testable" is exactly the sentence that deserves a
  second look.
- **Test files could pull a banned package into the agent's graph.** → They cannot: test-only imports do
  not link into the binary. This is verified by running `scripts/check-agent-deps.sh` after, rather
  than asserted from memory.

## Open Questions

- Whether the two `decodeMeta` implementations should be unified. This ticket deliberately does **not**
  merge them: fuzzing both is how one learns whether they actually behave identically, and merging them
  first would destroy the evidence. If both survive with identical behaviour, unification becomes a
  cheap follow-up with a fuzz corpus already backing it.
