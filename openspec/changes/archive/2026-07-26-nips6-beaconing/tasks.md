## 1. Detector
- [x] 1.1 `internal/analytics/beacon`: MAD-based regularity, median interval, jitter, allowlist,
      minimum contacts and minimum interval; ranked most-regular-first; input not mutated.
- [x] 1.2 Tests: metronome; jittered + one outage (**mutation:** stddev instead of MAD → FAILS); too few
      contacts (**mutation:** no minimum → FAILS); irregular browsing; bursts; allowlist (**mutation:**
      ignore it → FAILS); ranking; no input mutation.

## 2. Wiring
- [x] 2.1 `DetectBeaconing` over verified network-flow events, grouped per subject, deduped per
      (subject, destination, interval bucket), medium severity, closed-vocabulary title.
- [x] 2.2 Tests: a beacon alerts once across two sweeps; unverified flows produce nothing
      (**mutation:** drop `AND verified` → FAILS); a fleet's staggered polling is not a beacon
      (**mutation:** pool across subjects → FAILS); allowlist honoured; observation time is used
      (**mutation:** use receipt time → FAILS).

## 3. Gate and land
- [x] 3.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 3.2 Record D280; move NIPS-6 forward in the enrichment backlog.
- [x] 3.3 Sync specs and archive.
