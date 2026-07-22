# Design — bare-run precision guard

## Measure the inherent rate, bound against regression

A bare-run checksum detector's FP on random noise is arithmetic: ABA ≈ P(lead in the Fed range
~0.45) × P(mod-10 pass ~0.10) ≈ 4.5%; NPI ≈ P(lead∈{1,2} 0.20) × P(80840-Luhn pass ~0.10) ≈ 2%.
The measured values (3.98% / 2.00% over 20k runs, fixed seed) match, confirming the model. The
ceilings sit modestly above the inherent rate, so the honest rate passes while a constraint
regression — dropping the leading check takes ABA to ~10% — trips. This catches in AGGREGATE what
the isolated unit mutation tests catch case-by-case, and documents the tradeoff as a number rather
than a vibe.

## Why not drive it to zero

Bare-run detection is intentionally FP-tolerant: the detectors carry capped confidence (ABA 0.75,
NPI 0.80), and a policy consumes confidence, so a deployment that cannot tolerate the noise raises
its confidence threshold. Requiring context keywords or grouping would cut recall (real routing/NPI
numbers often appear bare). The guard makes the chosen tradeoff explicit and stable, rather than
silently changing it.
