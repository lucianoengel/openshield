## Context

`buildInput` already turns state into content-free policy inputs: classification hits, the exfil channel,
the behavioral findings, threat matches. ATT&CK mapping is one more derivation over those same signals —
a lookup from a signal to the technique it evidences — surfaced as `input.attack.techniques`.

## Goals / Non-Goals

**Goals**
- `internal/attack`: `Technique{ID, Name}` and `Techniques(Signals) []Technique` — a static mapping,
  deduplicated and sorted.
- `input.attack.techniques` in the policy input.
- Prove each signal class maps to its technique(s), signals combine, and no signal → none.

**Non-Goals**
- The full ATT&CK matrix (a curated starter set for the signals we produce).
- Sub-technique taxonomy / tactic grouping (refinements).
- Persisting techniques on the alert row (XDR-2 schema).

## Decisions

### D1 — Map the signals we already compute, curated and honest
The mapping covers exactly the signals OpenShield emits: credential detector types (private key, cloud
key, JWT, API token) → T1552 Unsecured Credentials; a known-bad destination (IOC domain/IP, URI
signature) → T1071 Application Layer Protocol (C2); cloud-sync exfil → T1567.002 Exfiltration to Cloud
Storage; removable-media exfil → T1052 Exfiltration Over Physical Medium; LOLBin → T1218 System Binary
Proxy Execution; encoded command → T1027 Obfuscated Files or Information; suspicious lineage → T1059
Command and Scripting Interpreter. It is a STARTER set, not the whole matrix — stated — so it never
over-claims coverage.

### D2 — A technique is evidence, mapped from a signal, not asserted by a detector
The detectors and analyzers stay ATT&CK-agnostic (they detect content/behavior); the mapping is a
separate, centralized table. This keeps the ATT&CK vocabulary in ONE place (easy to extend and audit) and
avoids smearing technique constants across detectors, and it means a technique is only ever emitted
because a real signal evidenced it — no free-floating tags.

### D3 — Deduplicated, deterministic output
Two signals can evidence the same technique (an IOC domain and a URI signature both → T1071); the result
is deduplicated by id and sorted, so `input.attack.techniques` is stable and a policy/consumer sees each
technique once. Content-free — a technique id and name carry no matched content (D10).

### D4 — Exposed as a derived policy input, reused by XDR
`input.attack.techniques` sits beside `input.event.behavioral` and `input.event.exfil_channel` — a
content-free derivation the LOCAL policy consults. XDR-4's sequence rules will consume the same
`attack.Techniques` mapping (reuse, not re-ticket), so the vocabulary is defined once for both routing
and correlation.

## Risks / Trade-offs

- **Starter-set coverage** — not the full matrix; extending the table is cheap and centralized, and the
  proposal states the limit so it is not mistaken for full ATT&CK coverage.
- **Signal→technique is coarse** — one signal maps to one/few techniques without sub-technique nuance; a
  refinement, and correct at the technique granularity SOCs mostly use.

## Migration Plan

Additive: a new package and one derived policy input. No proto/core/detector change; existing policies
are unaffected until they consult `input.attack`.

## Open Questions

- Whether to also group techniques by tactic (TA****) in the input. Deferred; techniques are the unit
  correlation and reporting use most.
