## Why

The network plane's threat engine (`internal/nips`) matches only **metadata** — destination domain,
IP/CIDR, and URI substrings. Its own package doc says so and names the gap: *"YARA-style body-content
signatures are a separate, worker-side follow-up."* Until that lands, a flow whose malicious payload
lives in the **body** (an exploit string, a C2 beacon marker, a known-bad request pattern) passes
uninspected — which is exactly the line ADR-8 draws: *"without signatures it is not an IPS."* This
increment crosses that line for **content**: an operator-authored content-signature ruleset, matched
against the flow body, feeding the same policy-prevent path the IOC matches already use.

## What Changes

- **New `internal/signature` package** — a `Ruleset` of content signatures. Each rule = an id + one or
  more literal content patterns (optional `nocase`) + an optional bounded RE2 regex + a closed category
  + a confidence. `Match(body []byte) []Hit` scans the body under a **bounded budget** (fail-open on
  over-budget: degrades to "scanned what we could", D13/D17). A `Hit` carries **only** the rule id +
  category + confidence — **never the matched bytes** (the D10 no-content boundary rule).
- **Ruleset file format + parser** (mirrors `nips.LoadFeed`: `#` comments, a malformed line is an error,
  never a silent skip) and a **hot-reload watcher** mirroring `nips.FeedWatcher`, with the baseline read
  **synchronously in the constructor** (the async-baseline race the test-isolation memory warns of).
- **Content matching runs in the sandboxed worker.** Content is attacker-controlled bytes, so the match
  runs in the seccomp/no-network worker that already parses request bodies (D72/D29/D35) — **never** in
  the network-capable gateway process. The worker loads the ruleset (`OPENSHIELD_NIPS_RULES`) and runs it
  over the body it already reads.
- **Proto (additive):** `ClassifyResponse.threat_matches` (a `repeated ThreatMatch`, field 6) carries the
  worker's content-free signature hits back across the IPC; a new enum value
  `THREAT_CATEGORY_CONTENT_SIGNATURE = 4`.
- **Policy-actionable:** the gateway's body-classify stage **merges** the worker-returned matches into
  `st.Threats` (the `input.threat` the policy reads), so a policy can **prevent** on a content-signature
  hit exactly as it does for an IOC hit. The engine never blocks on its own; its absence never denies
  (fail open).

## Capabilities

### New Capabilities
<!-- none — this is the named body-content follow-up of the existing network-threat-intel capability -->

### Modified Capabilities
- `network-threat-intel`: add content-signature matching over the flow **body** (in the sandboxed
  worker), its ruleset hot-reload, and its policy-prevent path — alongside the existing metadata IOC
  matching. The capability was explicitly scoped "metadata only … body-content signatures are a
  follow-up"; this delivers that follow-up.

## Impact

- **Code:** new `internal/signature/` (engine + parser + reload watcher); `internal/privileged` worker
  runs the ruleset and populates `ClassifyResponse.threat_matches`; `internal/gateway` merges worker
  matches into `st.Threats` and maps the new category; `cmd/openshield-worker` (or the worker start path)
  loads `OPENSHIELD_NIPS_RULES`.
- **Proto:** one additive field (`ipc.proto`) + one additive enum value (`threat.proto`); `make proto`,
  stage regenerated `pb.go` before `proto-check`.
- **Deferred (later increments, stated honestly):** full Suricata/Snort syntax (flowbits, per-protocol
  state, thresholding, offset/depth modifiers); Aho-Corasick multi-pattern optimization (increment 1 is
  linear per-rule); response-body scanning (shares NIPS-4's buffered path); and inline **DROP** actuation
  (root-gated NIPS-1 TPROXY — this increment is observe-then-policy-prevent via the existing flow-enforcer
  seam, no root).
