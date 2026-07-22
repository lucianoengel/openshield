# Tasks — bare-run precision guard
- [x] Measure ABA/NPI FP over 20k random 9/10-digit runs (fixed seed); log the rate.
- [x] Assert ABA ≤ 0.07, NPI ≤ 0.04 (measured ~0.04 / ~0.02).
- [x] Verify a constraint regression (drop ABA leading-range) trips the ceiling (~0.10).
- [x] make all clean; docs D144; sync; archive; commit; push; memory.
