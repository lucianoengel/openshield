# Design

## The four options, and why three were rejected

This was reviewed as a design decision rather than an implementation detail, because the failure modes
differ in kind rather than degree. Recording all four so the choice is auditable and so a future
reader does not re-derive the rejected ones.

### A — exempt the classifier processes by PID

The agent learns the engine's PID from the verdict socket via `SO_PEERCRED` — kernel-authenticated,
valid exactly while the connection lives, no configuration and no handshake — and exempts its process
group.

**Rejected.** The socket peer is not the opener: the sandboxed WORKER does `os.Open` on a
`ClassifyRequest_Path`, so the exemption has to cover the engine's children, which is process-group
bookkeeping rather than a fact the kernel hands over.

And its failure mode is the wrong shape. A stale or wrong exemption is a **silent bypass** — a process
inheriting a reused PID reads gated files unchecked — in a codebase that already treats PID reuse as a
live concern (HIPS-7 revalidates with start-ticks before a kill). Every other option fails toward a
stall or a fail-open, which is loud; this one fails toward a hole, which is not.

### B — keep the gating, suppress only the re-submission

No hole and no staleness, because the recursion was only ever in the resubmission and never in the
locking: the engine's server answers on a different goroutine from the one classifying.

**Rejected on its own**, because the nested gate decision needs a worker while the outer async
classification is holding one. Under load the pool exhausts, the nested decision times out and fails
open — **the gate stops gating exactly when it is busiest**, which is the shape of failure this whole
area keeps producing.

### C — ship the already-read prefix to the async tier

No new open, so no recursion at all. Adds containment on top of D358's audit row.

**Rejected as insufficient**, not as wrong: classification stays prefix-deep, so the whole-file claim
stays unmet. It remains the correct fallback if B′ ever proves too expensive.

### D — do nothing; rely on the file-watcher

Worth recording because it narrows the gap more than it first appears: the watcher already classifies
files fully ON WRITE, so a file written and then opened was already classified. The residue is files
written before monitoring started, or by a path the watcher misses.

**Rejected** because that residue is exactly the case an inline gate exists for — content that arrived
without the watcher seeing it.

### B′ — chosen

B, plus a **dedicated worker reserved for gate verdicts**. The nested decision always has capacity, so
B's failure mode disappears. One extra sandboxed process.

## The cycle breaker is path dedupe, not PID knowledge

The obvious break — "don't resubmit events caused by our own workers" — requires knowing which PIDs
are ours, which is option A's bookkeeping arriving through the back door.

Path dedupe needs none of it. Submitting async for a path suppresses further submissions for that path
within a short TTL. The async classification's own open still raises a gate event and still gets a
verdict; it simply is not resubmitted, so the loop terminates after one iteration.

**What it costs, stated rather than discovered:** a genuine second open of the same path within the
window gets a fresh VERDICT — the gate decides every open, always — but not a fresh async
classification. The file has not changed in between, so the second classification would reach the same
answer at the cost of another full read.

The cache is bounded and the TTL short. An unbounded map keyed by attacker-influenced paths is a
memory primitive, and this one lives in the engine, which is the process that must not fall over while
the gate depends on it.

## Why a separate pool rather than a larger one

A larger shared pool makes starvation less likely and does not remove it: under enough load the async
classifications still take every slot, and the nested decision still times out. Reservation is a
different property from capacity — the gate's worker cannot be taken by work the gate itself caused.

## What the VM test has to establish

Not that the async tier runs; that is provable without a kernel. **That the cycle terminates.** A
design that recurses would not fail a test, it would hang the host — so the assertion is bounded
resubmission under a real mark, and the mutation that removes the dedupe must be capped so the mutant
demonstrates the loop without bricking the machine.

ALLOW before DENY, every command under `sudo -n timeout N`, per the D352 ordering that exists because
this host was bricked twice.
