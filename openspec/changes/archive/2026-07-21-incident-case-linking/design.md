## Context

D104 (incidents) and D105 (cases) existed independently. Linking them is the natural
hardening.

## Goals / Non-Goals

**Goals:** open a case from an incident with a summary note, atomically.

**Non-Goals:** HTTP routes; automatic case creation; UI.

## Decisions

**Case and note in one transaction.** A case opened from an incident must carry the incident
summary — a case with no context is a worse artifact than no case — so both inserts share a
transaction and roll back together.

**The summary note is authored by the system, not a person.** The auto-note is attributed to
`system:correlation`, distinct from an operator's own notes, so the trail shows what was
machine-derived versus human-added.

## Risks / Trade-offs

- **Operator-triggered, not automatic.** Auto-opening a case per incident would spam; an
  operator decides which incident warrants a case. An auto-open policy is a deliberate
  follow-up, not a default.
