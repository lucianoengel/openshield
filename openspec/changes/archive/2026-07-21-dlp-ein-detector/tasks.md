# Tasks — EIN detector
- [x] DETECTOR_TYPE_EIN = 17 in proto; make proto.
- [x] ein detector: NN-NNNNNNN + IRS prefix whitelist, conf 0.60; register.
- [x] Test: assigned-prefix EIN detected; unassigned prefix + SSN grouping rejected.
- [x] Mutation: prefix whitelist bypassed → unassigned-prefix numbers trip.
- [x] make all clean; docs D143; sync; archive; commit; push; memory.
