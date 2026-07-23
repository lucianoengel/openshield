## 1. Proto (additive)

- [x] 1.1 `proto/openshield/v1/threat.proto`: add `THREAT_CATEGORY_CONTENT_SIGNATURE = 4` to `ThreatCategory`.
- [x] 1.2 `proto/openshield/v1/ipc.proto`: add `repeated ThreatMatch threat_matches = 6;` to `ClassifyResponse` (import threat.proto). Content-free: category+confidence+indicator_id only.
- [x] 1.3 `make proto`; `git add internal/core/corev1/*.pb.go` BEFORE `proto-check` runs its `git diff --exit-code`.

## 2. The signature engine (`internal/signature`)

- [x] 2.1 Types: `Rule{ID string, Patterns []Pattern, Regex *regexp.Regexp, Category corev1.ThreatCategory (or a light enum mapped in the gateway), Confidence float64}`, `Pattern{Bytes []byte, NoCase bool}`, `Hit{RuleID string, Category, Confidence}`, `Ruleset{rules []Rule, maxScan int}`.
- [x] 2.2 `(*Ruleset) Match(body []byte) []Hit`: per rule, ALL literal patterns present (nocase via a lowercased-body compare) AND regex matches (if set) → one Hit. Scan only the first `maxScan` bytes (bounded budget); a Hit NEVER carries matched bytes.
- [x] 2.3 `LoadRuleset(path)`/`ParseRuleset(io.Reader)`: `#` comments, blank lines skipped, a small fixed line grammar (id + category + confidence + patterns/regex); a malformed line → error (never a silent skip); empty ruleset = inert.

## 3. Hot-reload watcher

- [x] 3.1 `RulesetWatcher` mirroring `internal/nips/reload.go` FeedWatcher: read the baseline SYNCHRONOUSLY in the constructor; poll mtime; atomic swap (`atomic.Pointer[Ruleset]`); serve-stale + report on a parse error (never disarm).

## 4. Worker wiring

- [x] 4.1 The worker loads the ruleset once at start from `OPENSHIELD_NIPS_RULES` (absent → inert); runs `Match` over the body it already reads in the classify pass; maps each `Hit` to a `corev1.ThreatMatch{Category, Confidence, IndicatorId: rule id}` and sets `ClassifyResponse.threat_matches`.
- [x] 4.2 Confirm the worker seccomp profile still permits `regexp` + file read of the ruleset at start (the ruleset is loaded BEFORE the sandbox tightens, like other worker config); no network needed.

## 5. Gateway projection (the merge — decision 4)

- [x] 5.1 In `bodyClassifyStage.Run`, after the worker responds, project `resp.ThreatMatches` onto `st.Threats`: initialize `st.Threats` (a `*corev1.ThreatClassification`) if nil and APPEND the worker matches.
- [x] 5.2 Change the IOC `threatClassifyStage.Run` from `st.Threats = tc` to APPEND its matches into any existing `st.Threats` — so a flow with both a metadata IOC hit and a content-signature hit exposes BOTH to the policy (no overwrite).
- [x] 5.3 `cmd/openshield-worker` (or the worker start): read `OPENSHIELD_NIPS_RULES`; loud warn when unset (feature off), like the IOC-feed warn.

## 6. Tests (drive the REAL gateway→worker path, no seeded literals)

- [x] 6.1 `TestContentSignatureBlocksMaliciousBody`: real worker + gateway, a ruleset with a rule, a body containing the pattern, a prevent-policy → decision is BLOCK and a `THREAT_CATEGORY_CONTENT_SIGNATURE` match is on `st.Threats`.
- [x] 6.2 `TestCleanBodyNotFlagged`: a clean body → no content-signature match, flow allowed.
- [x] 6.3 `TestBothMetadataAndContentMatchReachPolicy`: one flow tripping BOTH an IOC domain and a content signature → the policy sees both matches (guards the merge/overwrite).
- [x] 6.4 `TestContentScanIsBounded`: an oversized body completes within budget (no hang), `truncated` surfaced.
- [x] 6.5 `TestRulesetReloadsOnChange`: add a rule to the ruleset file at runtime → a previously-allowed body becomes blocked, no worker restart (mirror `TestWatchFeedReloadsOnChange`).
- [x] 6.6 `TestSignatureHitCarriesNoMatchedBytes`: the `Hit`/`ThreatMatch` crossing the IPC carries the rule id but never the trigger substring.

## 7. Mutation verification

- [x] 7.1 Mutation — `Match` returns nil (engine inert): `TestContentSignatureBlocksMaliciousBody` FAILs. Revert.
- [x] 7.2 Mutation — `threatClassifyStage` overwrites (`st.Threats = tc`, the original): `TestBothMetadataAndContentMatchReachPolicy` FAILs. Revert.
- [x] 7.3 Mutation — watcher reads the baseline ASYNC: `TestRulesetReloadsOnChange` (or a startup-scan test) FAILs. Revert.

## 8. Gate & land

- [x] 8.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (test in background; `git checkout -- openshield-*` after any build; `make proto-check` clean).
- [x] 8.2 decisions.md D-entry; sync the delta into `openspec/specs/network-threat-intel/spec.md` (and update its Purpose prose: no longer "metadata only"); run doccheck (`go test ./internal/doccheck/`).
- [x] 8.3 Update the roadmap: NIPS-2 content-signature increment DONE (note it as increment 1; metadata IOC + content both now real); archive the change; commit, `git pull --rebase`, push.
