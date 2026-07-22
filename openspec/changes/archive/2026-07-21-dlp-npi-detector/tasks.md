# Tasks — NPI detector
- [x] DETECTOR_TYPE_NPI = 15 in proto; make proto.
- [x] npi detector: 10-digit + leading 1/2 + 80840-prefixed Luhn, conf 0.80; register.
- [x] Test: valid NPI detected; Luhn-off-by-one and wrong-leading-digit rejected.
- [x] Mutations: Luhn dropped (1234567894 trips); leading-digit dropped (3000000000 trips).
- [x] make all clean; docs D140; sync; archive; commit; push; memory.
