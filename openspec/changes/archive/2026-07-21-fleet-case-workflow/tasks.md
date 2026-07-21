# Tasks — case workflow with four-eyes (D105)

## 1. Cases

- [x] 1.1 Migration 011_cases.sql (cases + case_notes).
- [x] 1.2 Server.{OpenCase,AssignCase,AddNote,RequestClose,ApproveClose,GetCase}; ApproveClose four-eyes (up-front ErrFourEyes + atomic predicate); actors from verified cert identity.

## 2. Proof (Postgres; guards mutation-tested)

- [x] 2.1 **Test**: open→assign→note→request-close(Alice)→Alice self-approve REFUSED (ErrFourEyes, stays open)→Bob approves→closed recording both; approve-without-request refused.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D105.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| BOTH four-eyes guards removed | Alice then self-approves and the case closes (four-eyes bypassed) |
| up-front check removed only | SURVIVES — the atomic predicate still enforces four-eyes (defense in depth, honest) |
| atomic predicate guard removed only | SURVIVES — the up-front check still enforces four-eyes (defense in depth, honest) |
