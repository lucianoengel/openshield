# OpenShield

An open-source **Data Security Platform**. DLP is the first capability built on it, not the
product itself.

> **Status: pre-alpha. No working code yet.** What exists today is a decision record — the
> research, the adversarial reviews, and the plan. Published from the first commit deliberately,
> so the reasoning is auditable rather than reconstructed later.

## The idea

Everything moves through one fixed pipeline:

```
Event → Classification → Policy → Decision → Enforcement → Audit → Investigation → Analytics
```

New capabilities arrive as new **Event producers**, **Classifiers**, **Policies** and
**Enforcers**. The pipeline itself never changes. A change that requires editing the core is a
design failure, not a feature.

Detection and enforcement are kept completely separate, following CrowdSec's model: an Enforcer
receives only a `Decision`. It never learns which classifier matched, which regex fired, or how
confidence was computed. That separation is what lets enforcement points be written
independently.

## What it does and does not claim

This project takes honesty about its limits seriously, because its predecessors did not.

**It can:** give local-first visibility into data movement on Linux endpoints · create friction
and an audit trail for careless insiders · maintain a tamper-*evident* log with forward
integrity between anchors.

**It cannot:** prevent a determined person from exfiltrating data · stop anyone who has root on
their own machine · offer a tamper-*proof* log (impossible in a single self-hosted trust
domain) · reliably catch a motivated adversary who encrypts, screenshots or retypes.

The design centre is the **careless insider**, and most real data-loss events are careless.
Read [`docs/threat-model.md`](docs/threat-model.md) before drawing conclusions about efficacy.

## Design commitments

- **Local-first.** Classification, policy evaluation and enforcement happen on the endpoint.
  The server coordinates; it does not continuously control.
- **Privacy-first, honestly.** Only *type + confidence + count* leaves the endpoint. Hashing is
  **not** used as a privacy control for low-entropy identifiers (SSN, CPF, card numbers) —
  those keyspaces are brute-forceable and salting doesn't fix it. Embeddings and fuzzy
  fingerprints are treated as content-equivalent, never as de-identification.
- **Safe by construction.** The privileged process never parses attacker-controlled bytes;
  all content parsing runs in an unprivileged sandboxed worker.
- **Closed enforcement surface.** The action set is fixed and typed, so a compromised control
  plane cannot express "upload this file somewhere".
- **Privacy law is architecture.** Retention limits, purpose tagging, exclusion lists,
  pseudonymisation and view-auditing are Phase-1 features, not later additions.

## Where things are

| Path | What |
|---|---|
| [`docs/decisions.md`](docs/decisions.md) | **Canonical decision register (D1-D23).** Single source of truth. |
| [`docs/threat-model.md`](docs/threat-model.md) | What this stops, and what defeats it. |
| [`docs/plan-phase1.md`](docs/plan-phase1.md) | Phase 1 plan — 29 tickets, ~123 agent-hours. |
| [`docs/research-scouting-r1.md`](docs/research-scouting-r1.md) | Round-1 research: kernel hooks, policy engines, prior art. |
| [`docs/research-review-r1.md`](docs/research-review-r1.md) | Four adversarial reviews: architecture, cryptography, red team, law. |
| `openspec/` | Spec-driven development workspace. |
| `intake.md`, `case.md`, `tickets.*` | Working process files. |

Research reports are **append-only historical records** — they capture what was known at the
time and are never rewritten. Living documents reference decisions by number instead of
restating them.

## Roadmap

Phase 1 is **observe-and-audit only** on Linux: events are classified, policies produce
Decisions, and Decisions are recorded — but nothing is blocked. Enforcement arrives in Phase 2,
once the classifier's real false-positive rate is known from live data. A DLP tool that blocks
based on a noisy classifier is hostile to its own users.

Later phases add Cloud, Email, Developer and Collaboration security, identity-aware policies,
AI security, discovery, lineage and behaviour analytics — each as new connectors and enforcers.

## Licence

[Apache-2.0](LICENSE). Permissive, with an explicit patent grant. There is no field-of-use
restriction — see [`ETHICS.md`](ETHICS.md) for why that was a conscious choice and what we ask
of you anyway.
