# Tasks — Canadian SIN detector
- [x] DETECTOR_TYPE_CA_SIN = 14 in proto; make proto.
- [x] caSIN detector: grouped NNN-NNN-NNN + Luhn, conf 0.85; register.
- [x] Test: grouped Luhn-valid detected; off-by-one, grouped-invalid, bare-ungrouped, SSN-grouping rejected.
- [x] Mutation: Luhn dropped → grouped-invalid trips.
- [x] make all clean; docs D139; sync; archive; commit; push; memory.
