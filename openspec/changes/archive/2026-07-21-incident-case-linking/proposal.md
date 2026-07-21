## Why

F2 produces correlated incidents and F3 manages cases, but nothing linked them — an operator
re-typed the incident context into a new case by hand. This hardening closes the F2→F3 gap:
an incident becomes an investigation case in one step, pre-populated with its evidence.

## What Changes

- `Server.OpenCaseForIncident` — opens a case for an incident's subject and writes an
  opening note summarizing the correlation (alert count, peak risk, time span), in one
  transaction, attributed to `system:correlation`. `Server.CaseNotes` + `CaseNote` read the
  trail.

## Capabilities

### Modified Capabilities
- `control-plane`: a correlated incident opens a pre-populated investigation case.

## Impact

- `internal/controlplane/cases.go` (+OpenCaseForIncident, CaseNotes); `docs/decisions.md` D107.
- Proven (Postgres): an incident opens a case for its subject (opened by the operator, status
  open) with a single auto-note carrying the alert count and peak risk, authored by
  `system:correlation`; a subjectless incident opens no case. Guards mutation-tested
  (empty-incident; note-drops-count/risk). Case + note are one transaction (a case without
  its context would be a worse artifact than none).
- NOT in scope (stated): case HTTP routes (the methods sit behind the operator gate's
  identity); auto-open policy (an operator triggers it, not an automatic rule — avoiding
  case spam); the UI (F4).
