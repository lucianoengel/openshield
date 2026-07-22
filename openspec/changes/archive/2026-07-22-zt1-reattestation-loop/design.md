## Context

`posture.Attest` does one challenge→quote→publish round-trip. `retain.Loop(ctx, interval, fn)` is the
project's reusable ticker (cancellation-aware, disabled on a non-positive interval). Continuous
verification is the composition: call `Attest` immediately, then on every tick.

## Goals / Non-Goals

**Goals**
- `posture.AttestLoop`: immediate attest + periodic re-attest, cancellation-aware, best-effort errors.
- Fleet-agent wiring behind explicit config.
- Prove continuous verification: a good device stays attested; a drifted device loses it within a cycle.

**Non-Goals**
- Automated network enrollment (live credential activation) — the remaining follow-up.
- A verifier-side attestation TTL/expiry (the endpoint drives freshness by re-attesting; a server-side
  staleness timeout is a possible later refinement).

## Decisions

### D1 — Immediate attest, then `retain.Loop`
`retain.Loop` only fires on the ticker, so `AttestLoop` calls the attest attempt once up front (so a
device is attested promptly, not one interval late) and then hands the same closure to `retain.Loop`.
Reusing the tested loop keeps cancellation and the non-positive-interval guard consistent with the rest
of the codebase rather than reimplementing a ticker.

### D2 — Errors are logged, never fatal
A re-attestation failure (broker blip, a transient TPM error) must not kill the agent. Each attempt logs
on failure and moves on; the device is simply unattested until a later cycle succeeds — which fails
closed at the gate (D85), the safe direction. This matches how the posture/risk publishers treat a
publish failure.

### D3 — Continuous verification is the tested property
The point of the loop is not "it calls a function repeatedly" — it is that the gateway's `Attested`
signal tracks the device's *current* state. So the test drifts the device mid-loop and asserts the
gateway *rejects* the next re-attestation (its `Rejected` counter rises) and the device is no longer
attested. `Rejected` is a deterministic drift signal (a drifted quote always fails the PCR policy),
avoiding a dependence on the transient challenge-reset window.

## Risks / Trade-offs

- **Re-attestation cadence vs. load** — a short interval detects drift faster but costs a quote per
  device per interval; the interval is configurable, and a quote is cheap. Deployment tunes it.
- **Between challenge and report the device is briefly unattested** — inherent to the one-shot nonce;
  the gate fails closed during that window, which is correct (better a false-deny blip than a false-allow).

## Migration Plan

Additive: one endpoint loop function + fleet-agent wiring. No proto, verifier, or gateway change.

## Open Questions

- Whether a server-side attestation TTL should complement the endpoint loop (deny if no fresh
  re-attestation within N intervals). Deferred; the endpoint loop plus fail-closed-on-absent covers the
  main case.
