# Tasks

## 1. Proto
- [x] 1.1 `proto/openshield/v1/threat.proto`: `enum ThreatCategory {UNSPECIFIED, IOC_DOMAIN, IOC_IP,
  URI_SIGNATURE}`, `message ThreatMatch {ThreatCategory category, double confidence, string
  indicator_id}`, `message ThreatClassification {string event_id, repeated ThreatMatch matches}`. `make
  proto`; commit generated `corev1`.

## 2. Contract + policy
- [x] 2.1 `core.State.Threats *corev1.ThreatClassification` (doc: distinct from DLP classification, nil
  when no engine runs).
- [x] 2.2 `policy.buildInput` exposes `input.threat` = `{matches:[{category,confidence,indicator_id}],
  categories:{<name>:count}}` (absent/empty when no threats).

## 3. Threat-intel engine
- [x] 3.1 `internal/nips`: `Feed` (bad domains, IPs, CIDRs, URI substrings); `LoadFeed(path)` parses an
  operator file (one indicator per line: `domain evil.com` / `ip 1.2.3.4` / `cidr 10.0.0.0/8` / `uri
  /malware`), erroring on a malformed line; `Match(host, dstIP, path) []Match` (domain exact+parent
  suffix, IP exact+CIDR, URI substring; confidence 1.0). An empty/nil Feed matches nothing.

## 4. Gateway stage + wiring
- [x] 4.1 `threatClassifyStage` in `internal/gateway`: read `Event.GetNetwork()` (SNI/host, dst IP,
  path), run the matcher, set `st.Threats` (append; never errors the pipeline). Registered in
  `Process` only when a feed is configured (`Gateway.SetThreatFeed`).
- [x] 4.2 `cmd/openshield-gateway`: load the IOC feed from `OPENSHIELD_IOC_FEED` and set it on the
  gateway (a malformed feed aborts startup; no feed = engine inert, logged).

## 5. Tests
- [x] 5.1 Matcher units (no deps): domain exact + subdomain; non-matching sibling domain; IP exact; IP
  in CIDR; IP outside CIDR; URI substring hit + miss; empty feed matches nothing; `LoadFeed` round-trips
  and rejects a malformed line.
- [x] 5.2 Gateway integration (fake worker + ledger, no sockets): a flow to a feed-listed domain gets a
  threat match and a threat-blocking policy returns BLOCK; a clean flow gets no threat match and is not
  blocked by the threat rule; no feed configured → no threat stage, pipeline unchanged.
- [x] 5.3 Policy input: `input.threat.categories` reflects a domain match; `input.threat` is absent for
  a clean flow.

## 6. Mutation guards
- [x] 6.1 Make domain matching exact-only (drop the parent-suffix check) → the subdomain test (5.1)
  FAILs. Revert.
- [x] 6.2 Make the threat stage not set `st.Threats` (drop the matches) → the block-on-threat
  integration test (5.2) FAILs (policy sees no threat, does not block). Revert.

## 7. Record + close
- [x] 7.1 `docs/decisions.md`: new entry (D192) — NIPS-2 threat-intel engine; distinct threat dimension
  (not the DLP enum); definitive IOC confidence; metadata-only (YARA-body + live-refresh follow-ups);
  fail-open; NIPS-1 TPROXY root-gated pairing.
- [x] 7.2 `docs/architecture-roadmap.md`: mark NIPS-2 shipped (the gateway is now categorically an IPS on
  HTTP: DLP + threat-intel prevention).
- [x] 7.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` + `make proto-check` green; `GOOS=windows/darwin go
  build ./...`; `go test ./internal/doccheck/`; sync the delta into
  `openspec/specs/network-threat-intel/spec.md`.
