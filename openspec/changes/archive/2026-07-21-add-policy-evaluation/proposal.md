# Add local policy evaluation → Decision (T-008)

## Why

The classifier (T-007) emits evidence; nothing turns that evidence into a Decision. The pipeline
has a Decision stage-shaped hole between Classification and Audit, and the audit ledger,
replay, and the closed action set all already exist waiting for something to produce a
`Decision`. This change is that producer.

## What changes

**A policy stage in `internal/policy`** implementing `core.Stage`, evaluating a local Rego
policy (D6) against the pipeline `State` and emitting a `Decision`. No control plane — a fleet
of one distributes nothing (D1); the policy is a local file.

**The Rego engine is built with a RESTRICTED capability set.** OPA is instantiated with network,
clock and randomness builtins removed — `http.send`, `net.*`, `time.now_ns`, `rand.*`, `opa.runtime`
and bundle/loading features are not in the engine's vocabulary. A policy that references one
fails to prepare, at load time, with a named error. This is the load-bearing decision of the
ticket, and it does three things at once:
- **Makes "the server coordinates, it does not control" enforceable** (the brief's claim, D14's
  concern). When policy distribution arrives (Phase 2), a pushed policy still cannot make a
  network call, exfiltrate, or reach the clock — the capability set is the boundary, not review.
- **Makes decisions deterministic and therefore replayable** (D27, `core.Replay`). A policy that
  cannot read the clock or roll dice produces identical output for identical input, which is the
  acceptance criterion and the precondition for the audit trail being an investigation tool.
- **Removes an endpoint attack surface.** `http.send` in a policy engine on every endpoint is an
  SSRF/exfil primitive; it is simply absent here.

**The action is validated against the closed typed set (D14).** The policy returns an action by
name; the Go layer maps it to `corev1.Action` and rejects anything not in the enum with a hard
error. A policy — local now, distributed later — cannot express an action the enforcer contract
does not define. An unmapped action is a failed Decision, never a passthrough.

**Confidence flows from classification into the Decision (D4).** The policy consumes detector
confidence and count as thresholds and sets the Decision confidence; it is never coerced to 1.0.

**Phase 1 stays observe-only (D1):** the shipped default policy emits `ALERT`/`ALLOW`, never
`BLOCK`. The engine can express BLOCK — the type set is complete from day one — but the default
policy does not, and enforcement is Phase 2.

## What this does NOT claim or cover

- **No control plane, no policy distribution, no versioned rollout.** Local file only. The
  distribution seam is Phase 2 (T-023), explicitly out of scope.
- **No policy management UI or authoring tools.** A `.rego` file on disk.
- **It does not enforce.** It produces a Decision that is recorded (T-009) and, in Phase 1, acted
  on by nothing. Enforcers are Phase 2.
- **It does not make classification less noisy.** Garbage-confidence in, garbage-confidence out;
  the policy can only threshold what the classifier reported. The real false-positive rate is a
  T-015 measurement, not a policy claim.
- **The restricted capability set is not a sandbox for arbitrary computation.** It removes side
  effects and non-determinism; it does not bound CPU. A pathological policy can still be slow.
  Policy runs off the fanotify permission-response path (observe-only, and classification already
  reads whole files), so this is a throughput concern, not a machine-hang one — but it is stated,
  not hidden.

## Decisions

Depends on **D6** (OPA/Rego native, no custom IR), **D1** (observe-only; local policy for a fleet
of one), **D4** (confidence, not certainty), **D14** (closed typed action set), **D27**
(context_version for replay), and the T-007 classifier output.

Establishes a new decision: **the policy engine is instantiated with a restricted capability set
that excludes network, clock and randomness**, making distributed policy safe-by-construction and
decisions deterministic, rather than relying on review of policy content.
