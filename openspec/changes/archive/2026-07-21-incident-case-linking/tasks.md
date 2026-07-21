# Tasks — incident→case linking (D107)

## 1. Linking

- [x] 1.1 Server.OpenCaseForIncident (case + summary note in one tx, system-authored) + CaseNotes/CaseNote.

## 2. Proof (Postgres; guards mutation-tested)

- [x] 2.1 **Test**: an incident opens a case for its subject with a single auto-note carrying count+peak-risk (author system:correlation); a subjectless incident opens no case.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D107.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| empty-incident guard removed | a subjectless incident then opens a case |
| note drops incident count/risk | the summary-note assertion then fails |
