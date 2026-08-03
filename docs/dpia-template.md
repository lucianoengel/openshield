# Data Protection Impact Assessment — OpenShield deployment

> A DPIA is effectively mandatory for systematic monitoring of employees under GDPR Art. 35, and
> in Germany a works council holds an absolute co-determination right over such systems
> (BetrVG §87(1)(6)). This template is a starting point, **not legal advice** — complete it with
> your DPO and, where applicable, your works council, before deploying OpenShield to observe
> people's activity.

## 1. Description of the processing

- **What OpenShield does here:** observe-and-audit only in Phase 1 (no enforcement). It watches
  configured paths for file activity, classifies for specific PII patterns (CPF, credit card,
  SSN, email), and records a decision to a tamper-evident audit ledger.
- **What it records:** detector **type, confidence and count** — never the matched content, and
  never a reversible hash of low-entropy PII (design constraints D10/D11). The subject is a
  **pseudonymous** identifier (D23).
- **Scope of monitoring:** _list the hosts, paths, and user populations covered._
- **Exclusions configured:** _personal folders, break-time windows, and any other exclusion
  lists — an excluded subject produces no event at all._ Set them with
  `OPENSHIELD_EXCLUDE_PATHS` (path prefixes) and `OPENSHIELD_EXCLUDE_WINDOWS`
  (`HH:MM-HH:MM`, local time). Four things belong in this section, not in a footnote:
  - A **path** exclusion needs a coverage mode that yields resolved paths. Where the subject
    identity carries none, the exclusion cannot be applied; the agent observes the event and
    counts it as `privacy_exclusions_unevaluable`. **Record that number.** A non-zero count is
    the measured size of the gap in "these folders are not observed", and stating the exclusion
    without it overstates the control.
  - A **time** window needs only the event's timestamp, so it applies whatever identity the
    event carries. This half is complete.
  - An exclusion suppresses **observation**, never an enforcement verdict — an execution gate,
    a clipboard mediator, a print or mail decider still decides. Otherwise a break window would
    be a daily interval in which anything runs, which is a control users could invoke rather
    than one the operator holds. Say so when describing the exclusion, because a reader will
    otherwise assume the break window suspends everything.
  - An excluded subject is also **not protected**: nothing inside an exclusion is classified,
    so nothing there is contained either. That is the cost of the control and it is the
    operator's to accept explicitly.

## 2. Necessity and proportionality

- **Purpose:** _state the specific, legitimate purpose (e.g. preventing accidental disclosure of
  customer PII). Purpose is tagged on every event._
- **Why less-intrusive means are insufficient:** _document alternatives considered._
- **Data minimisation:** classification transmits type/confidence/count only; content stays on
  the endpoint. Retention is enforced with automatic purge (below).

## 3. Retention

- **Retention classes and durations:** routine telemetry (short), ordinary decisions (standard),
  investigation holds (retained until the investigation closes).
- **Erasure:** expired entries are **tombstoned** — their personal data is erased while the
  tamper-evidence chain is preserved. _State your configured durations._

## 4. Rights of data subjects

- **Transparency / notice:** _how are monitored employees informed? (A notice mechanism is a
  Phase-2 / enforcement-phase item; document your out-of-band notice in the meantime.)_
- **Access / erasure requests:** _process for handling them, noting the pseudonymous design._

## 5. Risks and mitigations

| Risk | Mitigation | Residual |
|---|---|---|
| Over-collection of personal data | type+count only; exclusion lists; retention purge | _assess_ |
| Misuse of the investigation view | every view is recorded to the audit ledger | viewer identity is unauthenticated until identity/enrolment ships (T-017) |
| Tampering with the audit trail | hash chain + forward-secure signatures; tamper-**evident** | a host-root attacker can destroy the log; completeness is only provable with external anchoring (T-019) |
| False positives affecting an individual | decisions carry confidence, not certainty (D4); Phase 1 does not enforce | _assess FP rate from dogfood (T-015)_ |

## 6. Consultation

- **DPO sign-off:** _____________________  **Date:** __________
- **Works council / employee representatives consulted:** _____________________
- **Review date:** __________

> OpenShield is tamper-**evident**, not tamper-proof. It can refuse an execution, a network flow, a
> print job, a clipboard paste and a USB device before they complete; it CANNOT prevent a file from
> being read, because reading the file is how it is classified — there, it contains after the fact.
> And anyone with root on a monitored host can defeat the agent. State these limits honestly in your
> own documentation — overclaiming a monitoring tool's capabilities is itself a compliance risk, and
> so is understating them if you rely on the understatement.
