## 1. The claim-surface check

- [x] 1.1 `internal/doccheck` package. `ScanClaimSurface(text) []Violation`: strip markdown
      emphasis, match the forbidden patterns, suppress a match that is negated on the line, escaped
      by `<!-- allow: <term> -->` on/above the line
- [x] 1.2 `ClaimSurfaces = []string{"README.md"}` — an explicit allowlist; scanning docs/ would
      recreate the false-positive failure
- [x] 1.3 Forbidden patterns: tamper-?proof, unhackable, fully/100% secure, impenetrable, prevents
      exfiltration/data loss, guarantees (security|safety|protection|your data)

## 2. The register check

- [x] 2.1 `CheckDecisionRegister(text) error`: extract every `**Dnn**`, fail on a duplicate

## 3. Tests + fixtures

- [x] 3.1 **Test**: the real `README.md` passes `ScanClaimSurface`. `TestREADMEIsHonest`
- [x] 3.2 **Test**: a good fixture passes; a bad fixture ("provides tamper-proof audit logs")
      fails. `TestClaimSurfaceFixtures`
- [x] 3.3 **Test**: an escaped use passes; a negated use passes. `TestQualifiedUsesPass`
- [x] 3.4 **Test**: the real `docs/decisions.md` has unique D-numbers; a collision fixture fails.
      `TestDecisionRegisterUnique`

## 4. Wiring + docs

- [x] 4.1 Run `go test ./internal/doccheck/` in the `invariants` CI job
- [x] 4.2 Note in `docs/decisions.md` (new D-number) the doc-consistency check and that the naive
      grep was rejected for false-positiving on honest discussion; the paragraph-length heuristic
      was replaced by the unique-D-number check for the same reason
- [x] 4.3 Mark T-029 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| negation suppression dropped (regress to naive grep) | `TestREADMEIsHonest` + `TestQualifiedUsesPass` — the honest README gets flagged, exactly the 2026-07-20 failure |
| register duplicate check disabled | `TestDecisionRegisterUnique` |

The real `README.md` passes (its uses are all honest negations: "cannot prevent",
"tamper-*proof* ... impossible"), and a planted "provides tamper-proof audit
logs" fixture fails — so the check is proven to catch the thing it exists for,
not merely to pass on today's tree. The negation-suppression mutation is the key
result: without it the check IS the naive grep, and it flags the honest README —
demonstrating in CI why the naive approach was rejected. The paragraph-length
heuristic the ticket originally suggested was deliberately replaced by the
unique-D-number register check, for the same reason the grep was rejected: it
would punish discussion. Wired into the `invariants` CI job.
