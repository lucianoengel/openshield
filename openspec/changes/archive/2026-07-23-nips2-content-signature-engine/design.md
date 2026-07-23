## Context

The gateway pipeline is: `net-classify` (body → sandboxed worker, `internal/classify` runs DLP
detectors) → `net-threat` (metadata → `nips.Feed`, sets `st.Threats`) → `policy` (OPA reads
`input.threat`) → decide. The worker is the only place attacker body bytes are parsed (D72/D29/D35).
The `nips` engine matches metadata only and defers body-content signatures by name.

Two existing seams matter:
- `ClassifyResponse` (ipc.proto) already carries content-free `DetectorHit`s from the worker.
- `st.Threats` (`*corev1.ThreatClassification`) is what the policy reads as `input.threat`; today the
  `threatClassifyStage` builds it from IOC metadata matches with `st.Threats = tc` (an **overwrite**).

## Goals / Non-Goals

**Goals:**
- Match operator content signatures against the flow body **in the worker**, content-free across the IPC.
- A signature hit is **policy-actionable** (prevent), reusing the existing `st.Threats`→policy path.
- Ruleset hot-reloads without a restart; a bad edit serves-stale (never disarms the engine).
- Bounded scan (no hang/OOM on a large or adversarial body); fail-open on over-budget.

**Non-Goals:**
- Full Suricata/Snort rule grammar, offset/depth/flowbits/thresholding, protocol-state matching.
- Aho-Corasick multi-pattern optimization (increment 1 is linear per rule; correctness first).
- Response-body scanning (NIPS-4's buffered path) and inline DROP (root-gated NIPS-1). Increment 1 is
  observe-then-policy-prevent via the existing flow-enforcer seam — no root.

## Decisions

1. **Placement: the worker, not the gateway.** Content signature matching parses attacker bytes, which
   is precisely what the seccomp/no-network worker exists to contain (D72). The gateway never runs a
   pattern over the body. The worker loads the ruleset once at start (`OPENSHIELD_NIPS_RULES`) and scans
   the body it already reads in the same pass as the DLP detectors.

2. **The IPC crossing is content-free.** The worker returns `repeated ThreatMatch threat_matches = 6` on
   `ClassifyResponse`. `ThreatMatch` is `{category, confidence, indicator_id}` — the `indicator_id` is
   the **rule id** (operator-authored), never the matched substring (D10). This is the same discipline as
   `DetectorHit` carrying type+confidence+count but no matched text. A test asserts the crossing carries
   the rule id and never the trigger bytes.

3. **New category, additive proto.** `THREAT_CATEGORY_CONTENT_SIGNATURE = 4` in threat.proto; the
   `threat_matches` field in ipc.proto. Both additive (no renumber), like the D215/D218 additive changes.
   `make proto`; stage regenerated `pb.go` before `proto-check` runs its `git diff --exit-code`.

4. **Merge into `st.Threats`, do not overwrite — the ordering trap.** The `net-classify` stage runs
   before `net-threat`. If `net-classify` sets `st.Threats` from the worker's signature matches and
   `net-threat` then does `st.Threats = tc`, the signature matches are **lost**. Fix: both paths APPEND.
   `net-classify` initializes `st.Threats` (or appends if present) with the worker matches; the IOC
   `threatClassifyStage` changes from `st.Threats = tc` to appending its matches to any existing
   `st.Threats`. A test with BOTH a metadata IOC hit and a content-signature hit on one flow asserts the
   policy sees both — this is the guard against the overwrite regression.

5. **Engine shape.** A rule: `{ID string, Patterns []pattern, Regex *regexp.Regexp, Category, Confidence}`
   where `pattern = {bytes []byte, nocase bool}`. `Match(body)` returns one `Hit` per rule that matches
   (all literal patterns present AND regex matches, if present — AND semantics within a rule, like a
   Snort rule's multiple `content:` needing all present). Bounded by `maxScanBytes` (scan only the first
   N bytes of an over-large body — a cap, not a bypass; the flow is still allowed/denied by whatever
   matched within the cap, and the truncation is surfaced). RE2 (`regexp`) has no catastrophic
   backtracking, so the regex itself is linear; the budget bounds total literal-scan work.

6. **Ruleset file format** (mirrors `nips.LoadFeed`): line-oriented, `#` comments, blank lines skipped.
   A rule line names the id, category, confidence, and its patterns/regex in a small fixed grammar;
   a malformed line is a load error (never a silent skip — a typo that drops a rule silently disarms a
   signature). `FileWatcher` re-parses on mtime change, swaps atomically, and **serves-stale** on a parse
   error; the baseline is read **synchronously in the constructor** so a write immediately after start
   cannot race an async first read (the memory'd async-baseline gotcha).

## Risks / Trade-offs

- **Merge correctness (decision 4)** is the sharpest risk: a silent overwrite would make every
  content-signature hit invisible to policy while all unit tests on the engine still pass — the classic
  "verifies against its own assumptions" trap. The both-hits-on-one-flow test is mandatory, not optional.
- **Budget vs. evasion:** a payload past `maxScanBytes` escapes the scan. Accepted for increment 1 (same
  trade as the DLP extraction budget); documented, and the truncation is surfaced (`truncated`), not
  hidden. A later increment can stream/window.
- **Linear per-rule scan** is fine for a modest operator ruleset; a large ruleset is an efficiency
  follow-up (Aho-Corasick), not a correctness issue — noted so it isn't mistaken for "done."
- **No root, no DROP:** increment 1 flags and lets policy prevent through the existing flow-enforcer
  seam. Inline packet DROP is NIPS-1 (TPROXY, root) — out of scope, stated so the IPS claim stays honest
  (prevention here = policy decision on an intercepted flow, not a kernel-level packet drop).
