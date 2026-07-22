# Tasks — PLAT-8 DSAR

- [x] `SubjectReport`/`SpanCount`/`AlertSpan` types.
- [x] `SubjectAccessReport(subjectID)` — audit + peer alerts + cases + legal hold; refuse empty subject.
- [x] `casesForSubject` helper.
- [x] `GET /subject` handler — operator cert identity, record-before-serve, operator-gated mount.
- [x] Test: full compile across stores, scoped; empty-subject-nothing-held; subjectless refused.
- [x] Mutations: audit query subject scope widened; legal-hold read hardcoded false.
- [x] `make all` clean.
- [x] docs/decisions.md D137; sync spec; archive; commit; push; memory.
