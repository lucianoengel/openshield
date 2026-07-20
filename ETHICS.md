# Ethics

OpenShield is employee-monitoring software. That deserves a stated position rather than
silence.

## The licence choice, made consciously

OpenShield is [Apache-2.0](LICENSE) — permissive, with **no field-of-use restriction**. Nothing
in the licence prevents this being used for invasive workplace surveillance, or by a state
against people it governs.

That was a deliberate decision, not an oversight. "Ethical source" licences such as the
Hippocratic License are **not OSI-approved** — they fail the Open Source Definition's
prohibitions on discriminating against persons, groups or fields of endeavour — and adopting
one would contradict this project's commitment to being genuinely open source. Restricting use
by licence also doesn't work: the people most likely to ignore a licence term are the ones you
would be writing it for.

So the licence is permissive, and the constraints live in the **design** instead.

## What the design does about it

These are product decisions, not aspirations — see [`docs/decisions.md`](docs/decisions.md):

- **Local-first classification.** Content stays on the endpoint. Only *type + confidence +
  count* leaves it. There is no architecture here for shipping employees' documents to a server.
- **No central behavioural profiling by default.** Peer-baseline UEBA — comparing a person
  against colleagues — is an optional module, **off by default**, with its own consent gate
  (D23). Self-baselines compute locally.
- **Exclusion lists are a first-class policy primitive** (D20), not a checkbox: personal
  folders and non-working time can be excluded structurally.
- **Pseudonymisation by default**, de-anonymised only on documented cause.
- **Investigations are audited** — the system records who *viewed* an investigation, not only
  who acted on it. Watching the watchers is part of the schema.
- **Four-eyes before HR-visible outcomes** (D20). A single investigator should not be able to
  escalate against a person alone.
- **A shipped DPIA template**, so deployers meet their obligations rather than discovering them.
- **Honest efficacy claims** ([`docs/threat-model.md`](docs/threat-model.md)). Overstating what
  monitoring achieves is itself an ethical problem: it justifies surveillance that doesn't work.

Notably, several of these are also what privacy law requires — GDPR Art. 35 DPIAs, works-council
co-determination, LGPD notice duties. Good privacy engineering and legal compliance point the
same way here, which is a useful signal that the design is sound.

## What we ask

The licence permits what it permits. Independently of it, we ask that anyone deploying this:

- **Tells the people being monitored** — what is collected, why, and for how long. Secret
  monitoring is indefensible even where it is technically lawful, and in Brazil (LGPD/CLT) and
  the EU it is generally not lawful either.
- **Uses the narrowest scope that solves the actual problem.** The exclusion lists exist to be
  used.
- **Does not use this against individuals as a pretext.** A tool that produces noisy signals
  (classification precision is genuinely poor) makes a terrible basis for action against a
  person. Keep humans in the loop and keep an appeal path.

## Who is responsible for what

The **deployer** is the data controller and carries the legal exposure under GDPR and LGPD, not
the authors of this software. Apache-2.0 §7 disclaims warranty and liability. That is the
standard and correct allocation — but it is a legal fact, not an ethical exemption, which is
why this document exists.
