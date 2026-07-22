# Tasks — ABA routing detector

- [x] Add DETECTOR_TYPE_ABA_ROUTING = 13 to the proto; make proto.
- [x] abaRouting detector: 9-digit candidate + leading-range + weighted mod-10 checksum, conf 0.75.
- [x] Register in classify.New().
- [x] Test: real routing numbers detected; checksum-off-by-one, out-of-range-lead, plain run rejected.
- [x] Mutations: checksum dropped (123456789 trips); leading-range dropped (990000000 trips).
- [x] make all clean (incl. proto-check).
- [x] docs/decisions.md D138; sync spec; archive; commit; push; memory.
