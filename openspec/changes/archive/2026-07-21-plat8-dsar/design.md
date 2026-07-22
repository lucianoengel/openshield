# Design — PLAT-8 DSAR

## Compile across the subject-keyed stores, don't invent one

Every store that holds subject data already keys it by the pseudonymous subject id: audit_entries,
peer_alerts, cases, legal_holds. The DSAR is a read that fans out over exactly those, so it needs
no new table and stays automatically complete as long as new subject-keyed stores add themselves
(a future store that holds subject data must extend the report — that is the honest coupling, and
it lives in one function). The report is a SUMMARY (counts, spans, case list, hold flag), not a
content dump: the point of a DSAR is the inventory, and the ledger's content is pseudonymous and
separately erasable under retention.

## Empty subject id is refused, empty result is not

`SubjectAccessReport("")` is an error — a DSAR must name a subject; an unbounded one would export
the whole store. But a subject with nothing held returns a well-formed empty report (zero counts,
nil time bounds, no cases, not held), because "we hold nothing about you" is a valid, informative
answer to a DSAR, not an error.

## The access is recorded before it is served

Reading everything about a subject is itself privacy-sensitive. The handler records the DSAR
against the operator's VERIFIED certificate identity (never a request field) via the same
`RecordView` log that backs `/view`, and records it FIRST — an attempted access is worth recording
even if the read then fails. The subject id is the recorded `subject_filter` and the access is
tagged `dsar`, so the investigation-views log distinguishes a DSAR from an event view.

## Mutation proof

Two guards pin the substance: the audit query's subject scope (widen it with `OR true` → the
report leaks another subject's entries, and the empty-subject case fails) and the legal-hold read
(hardcode false → the held-subject assertion fails). The report's correctness is otherwise a
composition of already-tested queries.
