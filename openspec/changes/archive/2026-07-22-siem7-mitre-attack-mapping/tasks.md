# Tasks

## 1. Attack mapping
- [x] 1.1 `internal/attack/attack.go`: `Technique{ID, Name string}`; `Signals` struct (detector types,
  threat categories, exfil channel string, behavioral flags LOLBin/EncodedCommand/SuspiciousLineage);
  `Techniques(Signals) []Technique` — a static signal→technique table, deduplicated by id and sorted.
  Mappings: credential detectors → T1552; IOC domain/IP/URI → T1071; cloud-sync → T1567.002; removable →
  T1052; LOLBin → T1218; encoded command → T1027; suspicious lineage → T1059.

## 2. Policy input
- [x] 2.1 `policy.buildInput`: build `attack.Signals` from the state (classification detector types,
  `st.Threats` categories, the exfil channel of a filesystem event, the behavioral findings) and expose
  `input.attack = {techniques: ["T…", …]}` (absent/empty when none). Content-free derivation.

## 3. Tests
- [x] 3.1 Mapping units: a credential detector → T1552; an IOC domain → T1071; cloud-sync + LOLBin →
  T1567.002 + T1218; removable → T1052; encoded command → T1027; suspicious lineage → T1059; two signals
  that map to the same technique de-dup to one; no signals → empty; output is sorted.
- [x] 3.2 Policy integration (real rego + dispatcher): a state with a cloud-sync exfil path and a
  credential classification → `input.attack.techniques` contains T1567.002 and T1552, and a policy that
  routes on a technique (e.g. BLOCK if T1567.002 present) fires.

## 4. Mutation guards
- [x] 4.1 Make `Techniques` not deduplicate → the same-technique-twice test (3.1) FAILs (a duplicate id).
  Revert.
- [x] 4.2 Make `buildInput` not populate `attack` (drop it) → the policy-technique-routing test (3.2)
  FAILs (the policy sees no technique). Revert.

## 5. Record + close
- [x] 5.1 `docs/decisions.md`: new entry (D201) — SIEM-7 ATT&CK mapping; signal→technique starter table;
  centralized/curated; content-free policy input; reused by XDR-4.
- [x] 5.2 `docs/architecture-roadmap.md`: note SIEM-7 shipped.
- [x] 5.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...`;
  `go test ./internal/doccheck/`; sync the delta into `openspec/specs/attack-mapping/spec.md`.
