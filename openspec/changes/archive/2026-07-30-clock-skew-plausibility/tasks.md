# Tasks

- [x] `plausibleObservationTime` — future-only plausibility, counted, with the past deliberately unbounded.
- [x] Wire into beaconing; report a future-dating agent once.
- [x] `OPENSHIELD_CLOCK_SKEW_TOLERANCE`; a malformed value falls back rather than removing the bound.
- [x] Test the decision directly, after establishing the end-to-end version cannot work.
- [x] Mutation: trusting the future must fail; ALSO bounding the past must fail beaconing.
- [x] Record what this does not close — backward skew, and why.
- [x] `make quick` green; targeted package tests only.
