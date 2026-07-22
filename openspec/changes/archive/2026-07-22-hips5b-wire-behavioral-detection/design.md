# Design — wire behavioral detection

## buildInput enrichment, not a new stage or a core-Context field

Three places could host the behavioral verdict: a new classify-domain stage (more moving parts, and
a new detector type), the frozen `core.Context` (a core change), or `buildInput` — which ALREADY
holds the event's exec metadata and already derives the aggregated hits it hands Rego. Enriching
buildInput is the smallest change that reuses an existing seam: it runs `behavioral.Analyze` on the
exec_path/parent_path/args it is already exposing, and adds a `behavioral` sub-document. behavioral
is pure and metadata-only, so running it in the engine (not the sandboxed worker) does not cross the
D29 content boundary.

## The policy decides; the default is observe-safe

The detector produces a SCORE and flags; the POLICY chooses the action from the closed set (T1). The
shipped default ALERTs at score ≥ 0.5 — never KILL — because a default that terminates processes on a
heuristic is unsafe. An operator who wants containment writes a KILL_PROCESS rule deliberately (and
HIPS-5a made that enforceable). File/network events carry no `event.behavioral`, so the rule is
undefined for them and cannot misfire.

## No conflicting decision

Rego `decision` is a complete rule; two definitions that yield different values for one input error
out. The PII-alert and behavioral-alert conditions are folded into a single `alert` flag, and
`decision` is ALERT-if-alert / ALLOW-if-not-alert — mutually exclusive. The `reason` mirrors which
condition fired (PII takes precedence when both hold, which process events never do).

## Mutation proof

Replacing the real exec metadata in the `behavioral.Analyze` call with empties drops the score to 0,
so the suspicious nginx→bash process no longer alerts — the test fails, proving the wiring is
load-bearing.
