## Context

This change documents shipped work. The design decisions were made and implemented in T-004,
T-030 and T-006; they are recorded here because they were not recorded at the time.

## Goals / Non-Goals

**Goals:** make `openspec/specs/` true again; give the agent process boundary a spec.

**Non-Goals:** changing any behaviour. The code is correct; the specs were behind it.

## Decisions

The three decisions this records are already in the register — D27 (`context_version`),
D28 (Context as a resolved value, closed set, absence fails), D29 (two binaries, and content
never reaching the privileged process). See [`decisions.md`](../../../docs/decisions.md).

### Why this was not caught by a mechanism

Every other invariant in this project is enforced by something that fails a build: import
checks, schema tests, negative compile tests, mutation-verified guards. Spec currency is not,
and it is worth being clear about why rather than pretending a check was overlooked.

A check that "the specs describe the code" requires knowing what the code means, which is the
thing specs exist to state. Approximations available — asserting that a commit touching
`*.pb.go` also touches `openspec/specs/`, or that every done ticket has an archived change —
are heuristics that produce false failures and get disabled, which is worse than no check.

So this boundary is held by process, and this project's own doctrine says process rots. The
honest mitigation is not a meta-check but keeping changes small enough that skipping one is
never a shortcut worth taking. This change exists as the evidence that it happened once.

## Risks / Trade-offs

- **Retroactive specs describe what was built rather than constraining what will be.** They can
  rationalise a design instead of testing it. → Mitigated slightly here: every requirement
  written corresponds to a test that already exists and was mutation-verified, so these are
  descriptions of proven properties, not aspirations. But the ordering was wrong and no amount
  of care afterwards recovers the design review that a proposal would have forced.

## Open Questions

1. Should a ticket be markable done without an archived change when it is capability work?
   Currently nothing prevents it. Making the roadmap the enforcement point is possible but
   ties two systems together that were deliberately separated.
