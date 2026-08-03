# Tasks — XDR-4c scheduled hunts

- [x] 1. Prove the collision: two hunts on one entity today produce one flip-flopping incident and one
      page.
- [x] 2. Migration `045_incident_rule_name.sql`: additive `rule_name`, both unique indexes reshaped.
- [x] 3. `CrossDomainRule.Name`; materialization keys and pages by (entity, rule).
- [x] 4. `LoadHunts(io.Reader)` — parse + validate against the domain and technique vocabularies,
      unique non-empty names, at least one sequence per hunt; every rejection names the hunt.
- [x] 5. `OPENSHIELD_CORRELATION_HUNTS` config entry; `loadHuntsFile` in the server; per-tick read.
- [x] 6. `RunCorrelationLoop` materializes the breadth rule plus every hunt on the same tick.
- [x] 7. The notification names the hunt.
- [x] 8. Unit tests + mutation verification.
- [x] 9. DB test: two hunts on one entity raise two incidents and page twice; a hunt raises an incident
      the breadth rule alone would not distinguish.
- [x] 10. Spec deltas (ADDED + MODIFIED) and README/roadmap.
