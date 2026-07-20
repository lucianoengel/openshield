# Contributing

## How this project is built — please read this first

**The code in this repository is written by AI agents, directed and reviewed by a maintainer
who does not write code personally.** This is disclosed up front so you can calibrate your
expectations rather than discover it later.

What that means in practice:

- **Commits are signed by the maintainer**, who takes responsibility for what lands. AI
  authorship is declared in commit trailers (`Co-Authored-By:` / `Generated-by:`).
- **Review capacity for incoming PRs is limited.** The maintainer can assess design,
  architecture and whether a change matches the decision record — but cannot review a subtle
  memory-ordering bug the way a working Go engineer would. Expect design discussion to be
  substantive and line-level review to be thinner.
- **Automated gates carry more weight here than in most projects**, because they substitute for
  review depth: CI, static analysis, import-boundary tests, fuzzing, and tests that assert
  security properties directly.
- **Copyright:** AI-generated code may not attract copyright in some jurisdictions absent human
  authorship, which is an open question for the Apache-2.0 grant. We do not claim authorship
  that cannot be legally backed. Your contributions remain yours under Apache-2.0.

If that model isn't one you want to contribute to, that's a reasonable position.

## Before proposing a change

1. **Read [`docs/decisions.md`](docs/decisions.md).** It is the canonical register of D1-D23.
   Many obvious-looking ideas were already considered and rejected for reasons recorded there —
   "just hash the PII" and "make the audit log tamper-proof" among them.
2. **Read [`docs/threat-model.md`](docs/threat-model.md)** before proposing anything about
   efficacy. If a change assumes the agent can stop a root user, it rests on a false premise.
3. If a change contradicts a D-number, that's allowed — argue against the decision explicitly
   and say what new information overturns it. Silent contradiction is what isn't allowed.

## Standards specific to this project

- **The pipeline is fixed.** Event → Classification → Policy → Decision → Enforcement → Audit.
  If a change requires editing the core rather than adding a plugin, that needs justification.
- **Never overclaim.** No "tamper-proof", no "prevents exfiltration", no "guarantees". CI greps
  docs for these words and fails the build. This is the project's known failure mode.
- **Negative properties need tests.** "Transmits no content" and "never parses untrusted bytes"
  are unfalsifiable as prose. State the test that proves it — an import allowlist checked by
  `go list -deps`, a wire-byte scan, a syscall audit.
- **Prefer mechanism over discipline.** Anything that depends on someone remembering will rot.
  Types, CI checks and boundary tests survive; conventions don't.
- Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`).

## How work is tracked

Three documents, three jobs, deliberately no overlap — an earlier setup kept two sources of
truth for the roadmap and they disagreed within a day:

| Job | Home |
|---|---|
| **Why** — decisions and rationale | [`docs/decisions.md`](docs/decisions.md) |
| **What / when** — roadmap and sequencing | [`docs/plan-phase1.md`](docs/plan-phase1.md) |
| **How / now** — active work | `openspec/changes/` |

This project uses [OpenSpec](https://github.com/Fission-AI/OpenSpec). Substantial changes start
as a proposal under `openspec/changes/` before implementation, referencing their ticket ID from
the roadmap. `openspec/config.yaml` carries the project context and the rules generated
artifacts must follow.

Not everything becomes a change. Spikes and measurements are throwaway code answering a
question; mechanical infrastructure has no design space worth specifying. Capability work — the
things with long-lived contracts — gets a change.

**"Keep going" is not an exemption.** This rule was broken three times in a row during a run of
consecutive implementation tickets, because momentum favours visible progress over the process
that keeps specs true. The result was measurable: two synced specs went stale against the code,
and the most security-critical capability in the repo shipped with no spec at all. It was
repaired by `add-agent-process-boundary`, which exists partly as the record that it happened.

If you are about to change a contract, a boundary or a protocol, and you are reaching for the
editor rather than `/opsx:propose`, that is the moment the rule is for.

Two OpenSpec sharp edges worth knowing:

- **Put `SHALL` or `MUST` on the FIRST line of a requirement.** The validator reads only that
  line, so a normative keyword on line two reads as a requirement with no normative keyword.
- **Archive syncs specs itself.** Running `/opsx:sync` first and then archiving makes the
  archive try to re-apply the same deltas and abort; use `openspec archive --skip-specs` if you
  have already synced.

## Reporting vulnerabilities

See [`SECURITY.md`](SECURITY.md). Please do not open public issues for suspected
vulnerabilities.
