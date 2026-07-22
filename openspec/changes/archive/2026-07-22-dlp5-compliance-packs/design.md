# Design — compliance packs

## Templates over authoring

The detectors already validate the data types each regulation cares about; a pack is just the Rego
that says "alert when any in-scope type is present". Shipping the three most-asked regimes (PCI,
HIPAA, GDPR) as embedded modules turns detector breadth into usable controls with an env var, not a
Rego-authoring project. The packs share the default's shape (in-scope hit → ALERT, else ALLOW) so
they run through the same restricted-OPA evaluation (no network/clock/rand) with the same guarantees.

## Sensitive by design

A compliance control should flag a VALIDATED occurrence, so the threshold is low (0.5): the detectors
only report when their format+checksum validated, so a hit above 0.5 is a real in-scope datum, not a
guess. This is deliberately more sensitive than the default's 0.85 strong-detector gate — a
compliance pack that missed a validated card number would be worse than one that over-alerts.

## Unknown pack fails loud

`NewPack` errors on an unknown name and the binaries abort startup — a compliance control that
silently fell back to "allow all" (or the permissive default) on a typo would be a false sense of
coverage. The pack id/version is stamped on each Decision, so the ledger records which regime applied.

## Proven

Each pack is tested to ALERT on an in-scope detector and ALLOW an out-of-scope one (PCI alerts on a
card but not health data; HIPAA on health/NPI but not a card; GDPR on email/SIN but not a card). An
unknown pack errors, and Packs() lists exactly the three.
