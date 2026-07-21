## Context

The watchdog (D18) already owns the permission answer under a hard budget, with the
self-PID exemption and the fail-open contract, behind an `Evaluator` seam — but nothing
ever produced a real BLOCK (Phase 1 only ever Allowed). Phase B's job is the Evaluator
that decides: a two-tier prefilter.

## Goals / Non-Goals

**Goals:** the synchronous decision logic — inline BLOCK on a cheaply-provable
high-confidence deny, fail-open otherwise, full classification always deferred to async.

**Non-Goals:** the real FAN_OPEN_PERM syscall + fd-passing (B2, external-gated); the
PartialDecider implementation (bounded worker classify); a new DENY_OPEN verb.

## Decisions

**Two tiers, and tier 2 always runs.** The prefilter submits the full-file async job on
EVERY path before it decides synchronously. Inline prevention never replaces the complete
classification, the durable audit row, or containment (D1/D16): even a synchronous ALLOW
is fully classified async; even a synchronous BLOCK still earns its durable record.

**Inline BLOCK only on high confidence (B3).** An inline DENY hangs then fails an open, so
it is reserved for a partial decision that is BLOCK AND confidence ≥ a floor (default 0.9).
A low-confidence partial hit — a guess off a bounded prefix — does NOT block inline; it
allows the open and lets the async tier fully classify and contain. Prevent only what you
can cheaply PROVE; contain the rest. `New` refuses a ≤0 floor (raises it to the default):
"block on any confidence" is not an accepted configuration.

**The prefilter never parses (D13).** It holds only the timing/decision logic behind two
seams. The bounded partial classification runs in the sandboxed worker (D72) via
`PartialDecider`; the async full job runs in the unprivileged engine via `AsyncSubmitter`.
The privileged agent that owns the fanotify fd never parses attacker bytes.

**Fail-open is the watchdog's job, reused.** A `PartialDecider` error returns
(VerdictAllow, err): the watchdog treats a non-nil error as a fail-open and audits it
loudly (D17), and because the async job was already submitted, the file is still fully
classified and contained. A slow prefilter is bounded by the watchdog's budget, not by
the prefilter itself.

## Risks / Trade-offs

- **The real permission path is untested here.** `fanotify_init(FAN_CLASS_CONTENT)` needs
  init-userns CAP_SYS_ADMIN; this session tested `--privileged --userns=host` rootless
  podman and it returns EPERM (container-root maps to the unprivileged host user). So the
  logic is proven behind the watchdog seam in plain Go, and the syscall adapter is
  external-gated to a host with genuine root — honestly, not hidden.
- **Bounded-prefix classification can miss** a hit past the prefix; that content is caught
  by the async full-file tier and contained, just not prevented inline. The two-tier model
  makes this trade-off explicit rather than pretending a full parse fits the window.
