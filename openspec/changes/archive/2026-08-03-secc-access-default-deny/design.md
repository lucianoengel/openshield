# Design — SEC-C access default-deny

## Why the no-match outcome is a stage property and not an engine default

The tempting fix is to make no-match DENY everywhere and call it hardening. It would be a worse defect
than the one being fixed.

The same `policy.Stage` runs the endpoint DLP pipeline, where an unmatched event is not an edge case —
it is nearly every event. A file write to a path no rule mentions, a DNS query for an ordinary domain, a
process exec of a normal binary. Denying those does not harden anything; it stops the machine, on the
first deployment, on every host. Observe-first (D1) is the correct answer there.

An access gate's unmatched request is the opposite: a caller nobody authorized, reaching an internal
service. Admitting it is the definition of the failure the gate exists to prevent.

Neither answer is more "secure" in the abstract; each is correct for what its stage decides. That is
precisely why the answer cannot live in the engine — an engine default is a single answer to a question
that has two.

The zero value stays ALLOW so every existing constructor and every test-constructed Stage keeps its
current behaviour, and `NewAccess` is the one place that opts in. A Stage built by some future
constructor that forgets to think about this gets observe-first, which is the direction that fails
visibly rather than silently.

## Why the load-time probe is needed on top of it

The two halves catch disjoint failures, and it is worth being precise about which:

- **The rule that is ABSENT** — deleted, shadowed, or never written. The module produces no decision,
  the no-match default fires, the request is denied. The probe cannot see this case at all, because the
  policy is not wrong; it is silent.
- **The rule that is PRESENT and wrong** — an unconditional allow, or a predicate that is vacuously true
  when the fields it reads are absent. The module DOES produce a decision, so the no-match default never
  fires. Only evaluating the module can find it.

`authorized if { input.context.role != "banned" }` is the realistic shape of the second. It reads like a
denylist, it is the kind of rule someone writes under time pressure, and it admits every caller whose
role could not be resolved at all — which includes every caller whose identity enrichment failed.

## Why two canonical principals

A NIL context is "no identity was resolved at all" — enrichment did not run, or ran and found nothing.
`input.context` is null, so `input.context.role` is undefined and a comparison against it is undefined
rather than false.

A ZERO context is "an identity resolved to nothing" — a caller authenticated at the transport, entitled
to precisely nothing. `input.context.role` is `""`, which is a defined value and compares.

A policy can pass one and fail the other, and the `!= "banned"` case is exactly that: undefined under
nil, true under zero. Probing only the nil shape would have accepted it. This is asserted by removing
the zero-context probe as a mutation.

## Why the probe input is built by buildInput

A hand-written `map[string]interface{}` would drift. The policy input has gained `risk_score`,
`device_posture`, `response_intent`, `binary_integrity` and the CASB `cloud` object at different times,
and a probe carrying a stale shape would evaluate a document no real request produces — passing, or
failing, for reasons unrelated to the policy. Building the probe through the same function that builds a
real request's document means the two cannot diverge without the compiler or a test noticing.

## What the ledger sees

The no-match denial carries its own reason ("no policy rule matched — the access stage denies by
default"), distinct both from an authored denial and from the observe pipeline's no-match allow. An
operator reading the ledger can tell "the policy denied you" from "no rule covered you": the first is a
decision, the second is a policy with a hole in it, and they call for different responses.

## Testing notes

The integration scenarios run the real binary because the claim is about a deployment, and they assert
the two halves separately:

- an incomplete policy DENIES an unmatched caller **and still serves an authorized one** — a
  default-deny that denies everyone is an outage, not a control, and is the plausible failure this
  change could introduce;
- a permissive policy stops the gateway starting, asserted through the readiness banner and a closed
  port rather than through process state. The harness does not reap its children until teardown, so an
  exited gateway is a zombie and every liveness check answers yes; the banner is printed where the
  listener is handed the connection, so its absence is the fact that matters.

Mutating the wiring back to `policy.New` fails both, the first with "an unmatched request REACHED the
internal service".
