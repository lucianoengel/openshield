# OpenShield architecture proposal — closing the gaps

> Companion to [`decisions.md`](decisions.md) (D1–D84) and [`architecture-roadmap.md`](architecture-roadmap.md). The roadmap set the *lens* (Producer / Classify / Context / Action-expansion / Data-plane / External-gating) and the phased order. This document commits to the *concrete design*: the packages, binaries, proto messages, `EventKind`/`Action` additions, `State.Context` inputs, enforcers, and connector shapes for each of the six capability areas — and, for each, the D26/D69 fitness proof that it lands in producers/classify/context/one-deliberate-action and leaves the frozen core untouched.

## Ground rules this document obeys

- **The frozen core is `internal/core`**: `Dispatcher` (with the `ResolveContext func(*corev1.Event) *core.Context` hook, D53, and `OnOutcome`), `State{Event, Classification, Context}`, `Stage`, `Registry`, `Enforcer`/`TargetedEnforcer` (`EnforceTarget(ctx, dec, target string)`), the forward-secure ledger (D30/D32/D46), and the `corev1` proto. Nothing below edits `Dispatcher.dispatch`, `State`, the `Stage`/`Enforcer` interfaces, or the ledger. The only permitted core-shaped edits are **additive proto fields/enums** (a new `oneof target` variant, a new `EventKind`, a new `Action` member with its `schema_test.go`/`validate.go`/`mapping.go` line) — the exact minimal, guarded shape D69 established for the network subject.
- **The boundary rule (D10/D29)** is absolute: content is classified in the process that already holds it (worker for files, worker-over-IPC for gateway bodies, D72) and only **type + confidence + count + metadata** cross a host boundary. Every new producer/detector below states where its content stays.
- **The action set is closed (D14).** New verbs are added **one at a time, each a distinct typed enum member with its own enforcer and its own guard** — never a parameterised/open framework. Each new verb below carries its D14 justification (why it cannot express "upload to URL") and its enforcer.
- **T1/T2/T3 are assumed resolved as the roadmap recommends** (expand actions one verb at a time; server computes risk but enforcement stays local via the D28 context seam; DLP-deep before XDR-broad). Where a *different* choice on any of these changes the design, it is flagged inline as **[T1-FLAG]/[T2-FLAG]/[T3-FLAG]**.

---

## 1. DLP (deep)

Today: four checksum-backed detectors (`internal/classify`, CPF/card/SSN/email, D33/D61), post-decision containment only (D49), single-platform (Linux fanotify NOTIFY-mode, D52). The gaps are inline prevention, detection depth, admin-authorable rules, and cross-platform.

### 1.1 Real inline prevention — the two-tier fast-prefilter / async-full design (solves D49)

The D49 blocker is exact: full classification reads whole files and cannot complete inside the fanotify permission window (532µs worst case, T-002/D19), so every Block would fail open (D17). The resolution is **not** "make classification faster" — it is to split the decision that answers the kernel from the decision that classifies.

**New package `internal/prefilter`** (a `core.Stage`, runs *inside* the permission window):

- Input: the `Event` and the file's **cheap, bounded** facts only — size, extension/MIME sniff of the first 4KB, path prefix against a watch/deny map, and an optional **content-free reputation** lookup (a Bloom filter of known-bad content fingerprints kept in the privileged agent — never the matched text, D10). No parser runs here (D33: RE2-class only; the prefilter runs *no* regex on full content).
- Output: a **provisional** `Decision` — it emits `ACTION_ALLOW` (the overwhelming common case, fits the budget) or the new **`ACTION_DENY_OPEN`** (§1.1.1) when a cheap signal is conclusive (oversized-from-a-crown-jewel-path, extension on the hard-deny list, fingerprint hit). Confidence is honest and low (D4) — the prefilter is a coarse gate, not the classifier.

**The async full path is unchanged**: after the kernel is answered (allow or deny), the same `Event` is queued to the existing `internal/engine` pipeline → worker (D29/D35) → full classify → policy → ledger. This is the **containment** tier (D49): if the full classifier finds PII the prefilter missed, the file is already open, so the response is `QUARANTINE_LOCAL`/`ENCRYPT_LOCAL` (existing enforcers) plus an alert — exactly today's post-decision behaviour, now *layered under* an inline gate rather than replacing it.

**Wiring:** the dormant watchdog/responder (D18, `internal/agent/watchdog`) is activated behind the prefilter in the privileged `openshield-agent` binary (currently an honest stub, D62/D84). The watchdog still owns the kernel answer under the fail-open contract: prefilter exceeds its own hard sub-budget → `FAN_ALLOW` + high-severity audit (D17/D18). **The prefilter's whole design premise is that it is fast enough to answer, and the watchdog is the proof-of-safety when it isn't.**

**Fitness (D26/D69):** the prefilter is a `Stage` (P/C-shaped); the async path is the existing pipeline; the only core-shaped change is one new `Action` (§1.1.1). Core untouched.

#### 1.1.1 New action: `ACTION_DENY_OPEN`

- **Proto:** `ACTION_DENY_OPEN = 7` in `corev1.Action`; one line in `internal/core/validate.go`; one line in `internal/policy/mapping.go` `actionNames`; the deliberate speed-bump edit to `schema_test.go`/`TestActionEnumIsClosed` (D69 precedent — adding an action is never silent).
- **D14 justification:** `DENY_OPEN` is a *single, typed, parameter-free* verb meaning "answer this pending fanotify permission event with `FAN_DENY`." It carries no URL, no path, no command — a compromised control plane distributing a policy that emits `DENY_OPEN` can, at worst, cause denials of file opens (a DoS, loud and audited), never exfiltration. It is strictly narrower than `BLOCK` (which today is a post-decision containment verb): `DENY_OPEN` is the *inline* verb bound to a live kernel permission event, distinct because its enforcement target is a pending fanotify response fd, not a file path. **[T1-FLAG]:** if the owner chooses *not* to expand the action set, inline prevention is impossible and OpenShield stays contain-after-the-fact forever — this is the sharpest place T1 bites.
- **Enforcer:** `internal/enforcers/denyopen` implements `core.TargetedEnforcer`; `EnforceTarget(ctx, dec, target)` where `target` is the fanotify response handle (the network-flow-id analogue, D69 pattern). It advertises only `ACTION_DENY_OPEN`; refuses anything else (D39 discipline). It lives in the privileged agent because only that process holds the fanotify fd — the worker never sees it.

### 1.2 Document-structure parsing + detector depth in the sandboxed worker

All of this lands in the **worker** (`internal/agent/privileged`, D29/D35) — the RCE-sandboxed, network-denied, seccomp/cgroup-bounded process the split was *built for* (D13, ClamAV CVE-2025-20260 is the whole rationale). No new core, no new proto except detector-type enum members.

- **New package `internal/classify/formats`** — bounded structural extractors for PDF/DOCX/XLSX/ZIP that yield a *text stream* the existing RE2 detectors run over. Every extractor sits behind the existing decompression-bomb guard (ratio/size/depth, D35) and the `max_bytes` ceiling in `ClassifyRequest` (already in the IPC proto). The parser is the attacker surface; it runs *only* in the worker (`check-agent-deps.sh` keeps `formats` out of the privileged agent binary, D29).
- **New detectors in `internal/classify/detectors.go`** — secrets (AWS/GCP/private-key/JWT/high-entropy, format+entropy, no network validation), health data (ICD-10 / NHS-number / structural), IBAN/passport (checksum-backed like CPF, D61), and a keyword/dictionary matcher (Aho-Corasick, linear-time — respects D33's RE2-class DoS bar). Each emits a new `DetectorType` enum member (`classification.proto`) with **type + confidence + count only** (D10/D33); confidence < 1.0 (D4); no matched text on the wire, asserted by the existing wire-byte grep.
- **Fitness:** pure C (classify plugins). The measured-quality discipline (D61) extends: each new detector ships with a labeled synthetic corpus and a regression guard on FP/recall.

### 1.3 Admin-authorable detectors + policy with SIGNED operator-approved distribution

This is where DLP meets the D14 red line: admins want to author rules, but "server pushes rules to endpoints" is exactly the control-plane-actuates threat D14 forbids. The resolution reuses the **Hub signing model already decided (D15)** — not a new mechanism.

- **New package `internal/rules`** — a *bundle* is `{detector_defs, rego_policy, metadata}` signed with ed25519 per-author, keys pinned at install, cached with expiry and **fail-closed when stale** (D15 verbatim). Detector defs are constrained to the RE2-class + checksum + dictionary shapes above (a bundle cannot introduce a backtracking engine — D33 enforced at load, like OPA's nondeterministic-builtin filter D34).
- **The distribution rule (D14/D15):** the control plane *offers* a bundle; the **endpoint operator approves and installs it** (a local action, mirroring `issue-token` and `openshield-provision` being admin-local authority binaries, D51/D60). The server never silently pushes an active rule. A bundle whose signature fails, whose author key is unpinned, or whose cache is stale is refused, loudly (D15). Policy content is still loaded into the D34-restricted OPA (no `http.send`, no clock, no rand) — an authored policy *cannot* reach the network regardless of who signed it.
- **Fitness:** C + a distribution decision, no core change. The bundle is data consumed by the existing classify/policy stages. **[T1-FLAG/D14]:** the one thing a bundle can *never* carry is a new `Action` — the action set is a compile-time enum, not bundle content, so an authored policy can only select from `{ALLOW, ALERT, BLOCK, QUARANTINE_LOCAL, ENCRYPT_LOCAL, REDIRECT, DENY_OPEN, …}`. This is the structural reason authored rules are safe.

### 1.4 Cross-platform producer/enforcer split (core stays portable)

The core is all-Go and portable (D8); the OS-specific parts are **producers and enforcers only** (the roadmap's E-gated item). This is a design statement, not a build:

- **Windows:** `internal/connectors/minifilter` (a producer emitting the same `FilesystemSubject` events via a signed minifilter driver — the EV-cert/attestation gate is D9, external) and `internal/enforcers/win` (deny-open via the filter's pre-operation callback — the natural home for `DENY_OPEN`). The minifilter is the Windows analogue of the fanotify connector (D52); it produces paths, never content (D29), and hands bytes to a Windows worker for classification.
- **macOS:** `internal/connectors/endpointsecurity` (an Endpoint Security `ES_EVENT_TYPE_AUTH_OPEN` producer — the entitlement is D9, external) and `internal/enforcers/macos` (auth verdict = `DENY_OPEN`).
- **Fitness:** three producers + two enforcers, all P/A-shaped, all outside core. The *same* `corev1.Event`/`Decision`/`Ledger` flow; the *same* `DENY_OPEN` verb and enforcer contract. This is the payoff of D8 (one language ⇒ one pipeline ⇒ parity deleted not solved): the classifier, policy, ledger, and action set are identical across OSes; only the kernel hook and the enforcement syscall differ. **Most enterprise data lives on Windows/macOS, so this gates real-world DLP relevance more than any feature (roadmap).**

---

## 2. HIPS

**[T3-FLAG]:** HIPS is the explicit XDR bet, not the default trajectory — the roadmap recommends DLP-deep first. Everything below is a *separately-scoped* subsystem. It fits the pipeline cleanly; the question is product scope, not architecture.

### 2.1 Exec-event producer — pick fanotify `FAN_OPEN_EXEC_PERM`, justified

Three candidates: `FAN_OPEN_EXEC_PERM` (fanotify), eBPF-LSM, auditd.

- **Chosen: `FAN_OPEN_EXEC_PERM`.** Rationale: it *reuses the fanotify machinery already built and understood* (D3/D52, the connector, the permission-mode watchdog D18, the fail-open contract), it can **block inline** (the permission variant, the whole point of HIPS), and it needs the same `CAP_SYS_ADMIN` the agent already has. eBPF-LSM is more powerful (arg/env visibility, `bprm_check_security`) but is a *second* privileged mechanism with its own kernel-version matrix and its own verifier surface — a large new attack surface in the privileged process, against D7 (keep the core small) and D13 (minimise what runs privileged). auditd is observe-only (no block) and a noisy log-scraping path. **Decision: `FAN_OPEN_EXEC_PERM` now; eBPF-LSM is a documented later bet if arg-level lineage proves necessary.**
- **New producer `internal/connectors/exec`** — emits a new `EventKind EVENT_KIND_PROCESS_EXEC = 8` carrying a new `oneof target` variant **`ProcessSubject`** (`proto`): `{exec_path, pid, ppid, parent_exec_path, uid_pseudonym, cmdline_hash}` — **metadata only**, no full argv content on the wire (D10; argv can carry secrets — treated content-like, hashed or dropped like the gateway's `http_path`, D77). Pattern-identical to `NetworkSubject`/`UsbSubject` (D69): a new `oneof` arm beside `filesystem`/`usb`/`network`.

### 2.2 Behavioral classify domain

- **New package `internal/classify/behavior`** — a *different classifier shape* than content patterns (roadmap E2): allow/deny-listed exec paths, LOLBin detection (a curated list — `bash`/`powershell`/`certutil`/`rundll32` spawned from unusual parents), and **process-lineage** rules (`office → cmd → powershell` chains). Lineage is *stateful and cross-event*, exactly the new shape peer-UEBA established needs the context seam (D53). So lineage state is resolved into `State.Context` via the `ResolveContext` hook, **not** accumulated inside a stage — the same discipline D53 enforced. A new `Context` field **`ProcessLineage []LineageHop`** (closed typed, D28 — not a map) carries the resolved ancestry the policy consults.
- **Fitness:** P (exec producer) + C (behavior classifier) + X (lineage context via D53 seam). The one core-shaped addition is the `ProcessSubject` proto variant + `EVENT_KIND_PROCESS_EXEC` — additive, the D69 shape.

### 2.3 Deliberate action verbs: `ACTION_DENY_EXEC` and `ACTION_KILL_PROCESS`

Two *distinct* verbs, each its own enforcer and guard (T1, one-at-a-time):

- **`ACTION_DENY_EXEC = 9`** — answer a pending `FAN_OPEN_EXEC_PERM` with `FAN_DENY`. Inline prevention of *execution*. Enforcer `internal/enforcers/denyexec` (`TargetedEnforcer`, target = the exec permission fd). **D14:** a single typed verb; cannot express anything but "refuse this exec." A compromised control plane emitting `DENY_EXEC` causes a loud, audited execution-denial DoS — never code execution *by* the platform. This is the inverse-safe property: the closed set can only ever *withhold*, never *invoke*.
- **`ACTION_KILL_PROCESS = 10`** — send `SIGKILL` to an already-running pid. Distinct from `DENY_EXEC` because its target is a live pid (not a permission fd) and its semantics are terminate-not-prevent — a genuinely different capability that must be reviewed on its own merits (T1). Enforcer `internal/enforcers/killproc` (`TargetedEnforcer`, target = pid). **D14:** `KILL_PROCESS` is the *most* powerful verb in the set and the strongest test of T1 — it can terminate arbitrary processes. It is justified only because it is *typed and parameter-free* (kill *this* pid, from *this* event's lineage) and audited decision-first (D49). **[T1-FLAG]:** this is the verb where a conservative owner might stop — `DENY_EXEC` (prevent) is defensible; `KILL_PROCESS` (actuate on a running process) is where "the server informs, the endpoint decides" (T2) matters most. Under T2 the *server* never emits `KILL_PROCESS`; the *local* policy does, from local lineage + published risk.

### 2.4 FIM / integrity monitoring

- **New producer `internal/connectors/fim`** — watches a configured set of integrity-critical paths (via the existing fanotify `FILE_MODIFIED` events, D52, plus periodic hashing in the worker). Emits existing `EVENT_KIND_FILE_MODIFIED` events; a new detector `internal/classify/integrity` compares a worker-computed content hash against a **signed baseline manifest** (reuse the D15 signing model, like the rule bundles §1.3). A drift is an `ALERT`. The baseline hash is computed and held in the worker (content stays there, D29); only "path X drifted from baseline" (a boolean + path) crosses.
- **Fitness:** P + C, no new action (drift is `ALERT`). Reuses the existing file pipeline entirely.

---

## 3. NIPS / NDR

Today the gateway is a **configured forward proxy** over HTTP(S) with TLS interception (D73–D75), one-way-pseudonymised `sha256(src-IP)` subject (D77/D84), request-body classification in the worker (D72), worker pool (D76), boundary-safe projection (D77). D84 states plainly it is **not** a NIPS (only proxied HTTP(S)) and **not** a ZT enforcement point (no authenticated subject). This section removes the "must configure a proxy" limit and adds non-HTTP breadth.

### 3.1 Transparent / inline data-plane connector (D — new topology, not new core)

- **New package `internal/gateway/transparent`** — an nftables `TPROXY`/`REDIRECT` (or an L2 bridge / `AF_PACKET`) front-end that hands intercepted connections to the *existing* `gateway.Proxy` via the divert socket, instead of requiring the client to be configured with `http_proxy`. The flow-table (`internal/gateway.Table`, D73) and `NetworkSubject`/`flow_id` contract (D69) are **unchanged** — the connector just changes *how a connection arrives*, exactly as the roadmap's C1 predicts. `flow_id` still resolves to a live connection the owning handler disposes (allow/block/redirect, D73); block-vs-reset stays an enforcement *mode* (D69), now including a real TCP RST via the raw socket.
- **Fitness:** pure D (new connector topology). The pipeline, worker classification (D72), enforcer (`internal/enforcers/flow`), and projection (D77) are identical. **This is the single change that makes OpenShield a real inline NIPS data plane rather than a forward proxy — and it needs zero core change**, which is the D69 fitness claim holding under a genuinely new data-plane shape.

### 3.2 Non-HTTP producers — DNS, SMTP, raw L4

- **DNS proxy `internal/gateway/dns`** (the top NDR gap — DNS-exfil and C2-over-DNS): a DNS resolver/forwarder producing a new `EVENT_KIND_DNS_QUERY = 11` with new `NetworkSubject` fields `qname`, `qtype`, `response_size`, `nxdomain_ratio` (all metadata; the qname is a hostname, metadata not body). A new classifier `internal/classify/dnsexfil` (entropy of qname labels, query-rate/NXDOMAIN anomaly — stateful, so it uses the `ResolveContext` seam like peer-UEBA, D53). Verdict: `ALERT`, or `BLOCK` (refuse the resolution) via the flow enforcer.
- **SMTP `internal/gateway/smtp`** — an SMTP proxy; the message body is classified in the worker (D72, inline `content` IPC variant already exists) — DLP over email egress, reusing every existing detector.
- **Raw L4/TCP metadata `internal/gateway/l4`** — `EVENT_KIND_NETWORK_FLOW` (already exists, D69) for non-HTTP TCP/UDP: connection 5-tuple, byte counts, timing (beaconing signal). Metadata only — no body.
- **Fitness:** P + C. New `EventKind` members and `NetworkSubject` field additions (additive, D69 shape). Each protocol *parser* runs in the sandboxed worker (D72/D35), never in the socket-holding gateway process — the D71 discipline extended to every new protocol.

### 3.3 Response-body / multipart / decompression at the gateway

- **New classify plugins in the gateway's worker path** — the gateway already reads the request body bounded (D73) and classifies it in the worker (D72). Extend the same worker `ClassifyRequest{content}` path to (a) response bodies, (b) `multipart/form-data` part-splitting, (c) `Content-Encoding: gzip/deflate/br` decompression — all behind the existing decompression-bomb guard (D35). These are the `internal/classify/formats` extractors from §1.2, reused. **Fitness:** pure C, in the worker.

### 3.4 IDS-signature classify plugin (optional)

- **`internal/classify/signatures`** — a Suricata/Snort-ruleset-style matcher as a *network classify plugin*, running in the worker over the flow metadata + body. It emits `ALERT`/`BLOCK` like any classifier. Kept optional and RE2-class-bounded (D33: a ruleset must not introduce catastrophic backtracking). **Fitness:** pure C. No new action — signature hits map to the existing verdicts.

---

## 4. SIEM

This is the server-side surface *above* the pipeline, built on the operator read API (D82) and alert delivery (D83). None of it touches the endpoint pipeline or core — it is analytics over the fleet aggregate (`fleet_telemetry`, `peer_alerts`, D41/D54) and ingested third-party logs.

### 4.1 Query / search API

- **Extend `internal/controlplane/operator_read.go`** (D82 gave `/alerts`, `/overdue`, `/view`) with `GET /search` — filter/facet/time-range over `fleet_telemetry` and `peer_alerts`. Read-only, holds no signer (the D30 read/write asymmetry — a reader forges nothing), mounted behind the mTLS `requireRole(RoleOperator)` gate (D58/D82). Returns pseudonymous subjects only (D23); no content ever stored to query (D41 — the aggregate is boundary-safe by construction). Pagination/filtering beyond D82's `limit`/`threshold`.

### 4.2 Correlation / rules engine (cross-host, cross-event)

- **New package `internal/analytics/correlate`** — peer-UEBA (`internal/analytics/peerueba`, D53/D54) is the *seed*: a stateful, cross-entity analyzer over the *verified* telemetry stream (D50). Generalise its shape: a rule engine consuming the verified stream and emitting **derived** `peer_alerts`-style records into a new `correlations` table, **deliberately apart from received telemetry** (a derivation must not masquerade as agent-attested evidence — the exact D54 discipline). Rules are cross-host ("same subject uploads to new-domain across 3 endpoints"), cross-event ("file-staging FIM drift then large egress flow"). **It observes — no risk is fed back to agents as a command** (D54/D14); risk is *published* for local policy to read (T2, §5.5).
- **State/HA:** peer-UEBA/correlation state is currently in-memory (D53/D61). For a real SIEM this must be **persistent and HA** — a new `internal/analytics/store` backing the analyzer state in Postgres (baselines, decay clocks, cooldowns) so a control-plane restart doesn't reset every baseline and a second control-plane replica sees the same state. This is the honest scale gap D54's "toy z-score" understates.

### 4.3 Case / investigation workflow (four-eyes, assignment, notice — T-013 remainder)

- **New package `internal/controlplane/casework`** — builds on the view-accountability seam (`Server.View`/`RecordView`, D47/D56, `investigation_views`). Adds: case creation from an alert, **assignment** (operator-cert-bound, D58), **four-eyes gating** (D20/D36 — an HR-visible outcome requires two distinct operator identities; enforced by the cert-role gate requiring two `operator:<CN>` approvals recorded before a case can transition to an HR-visible state), and **employee notice** (D20, BetrVG works-council posture). All writes are operator-authenticated via mTLS (D56/D58); all views recorded (D47). This is the T-013 remainder D36 explicitly deferred to the write-capable control plane.

### 4.4 Dashboards / UI

- **New binary/asset `cmd/openshield-ui`** (or served by `openshield-server`) — a UI over the D82/§4.1 read API and §4.3 casework. It is a *pure consumer of the JSON API* (D82: "this JSON API is the substrate a UI would sit on"), holds no signer, authenticates as an operator cert. No new core, no pipeline involvement.

### 4.5 Third-party log ingest (syslog)

- **New producer `internal/controlplane/ingest/syslog`** — if OpenShield becomes a SIEM (not just its own telemetry), a syslog/RFC5424 receiver that normalises third-party logs into the aggregate for correlation. **Boundary consideration:** ingested logs are *not* signed agent telemetry (D50), so they land in a **separate `external_logs` table marked unverified** — never conflated with the verified stream that drives peer-UEBA (D50/D54: only verified telemetry moves a baseline). Schema/retention: the D81 retention loop (`internal/retain.Loop`) extends to `external_logs` and `correlations` with their own windows (D20 enforced retention).
- **Fitness:** all F is server-side, above the pipeline. **[T3-FLAG]:** §4.5 is the point where OpenShield stops being "a DLP that reports to a server" and becomes "a SIEM." That is an XDR-scope decision — the roadmap recommends deferring it until the DLP core is deep (T3).

---

## 5. Zero-Trust VPN / identity-aware access — the headline capability

This is the sharpest overclaim closed (D84 explicitly reframes "Zero Trust oriented" as *false today*: the gateway authenticates no subject — `sha256(src-IP)` is not an identity). The design turns the existing **forward/egress** proxy into an **identity-aware reverse/access proxy** brokering client access to internal services (BeyondCorp/Tailscale-style), reusing the D69 flow-table, D73–D75 proxy, D60 CA, and D82/D83 control-plane. The genuinely new pieces are: an **identity producer**, a **device-posture context input**, a **reverse/access-proxy mode**, and an **internal-service catalog/policy**.

### 5.1 Reverse/access-proxy mode (new topology on the existing proxy)

- **New package `internal/gateway/access`** — a mode of `internal/gateway.Proxy` that **terminates client connections to *internal services*** (the reverse direction) rather than proxying a client's egress to the internet. The proxy already terminates TLS and mints leaves (`CertMinter`, D75) and owns the connection lifecycle/disposition (D73). Access mode differs in *what it fronts*: a catalog of internal services (`payroll-api.internal`, `wiki.internal`) instead of arbitrary upstreams. The flow-table (`Table`, D73) and `flow_id` disposition (allow/block/redirect, D69) are **reused unchanged** — a denied access request is a `flow_id` set to block, exactly as an egress block.
- **Fitness:** D (new connector topology, reverse instead of forward). The pipeline, worker classification, and flow enforcer are identical.

### 5.2 Identity producer — authenticate a verified SUBJECT (replaces `sha256(src-IP)`)

- **New package `internal/gateway/identity`** — runs at the gateway *before the pipeline*, authenticating the client by **either**:
  - **client certificate** issued by the provisioning CA (`internal/provision`, D60 — the *same* `IssueCert` machinery, a new `RoleClient` beside `RoleAgent`/`RoleOperator`, subject OU carrying the role, verified exactly as the D58 cert-role gate verifies operator/agent), **or**
  - **OIDC/bearer assertion** (a new `internal/gateway/identity/oidc` verifier — validate the token signature/issuer/audience, extract subject+groups). OIDC verification is a pure signature/claims check — no `http.send` into the pipeline (the D34 discipline; token introspection, if needed, happens in the identity layer *before* the pipeline, never inside policy).
- **Output:** a **verified, still-pseudonymised** subject (D23 — the mapping to a real identity stays behind an audited lookup, D23/D47) plus the raw role/groups. This **replaces the `sha256(src-IP)` subject** (D77/D84): the `Subject.pseudonymous_id` on the `NetworkSubject` event is now `H(verified-identity)` not `H(src-IP)` — an identity-derived pseudonym, the whole point.
- **Fitness:** P (a producer/auth layer at the gateway) — the roadmap's A1, "the real work." It reuses the D60 CA and the D58 cert-role verification pattern.

### 5.3 Device posture as a typed Policy context input (the D28/D53 seam)

- **New `Context` fields in `internal/core` (D28, closed typed set — NOT a map):** `Identity string` (pseudonymous, D23), `Role string`, `DevicePosture DevicePosture`, and the existing `RiskScore`/`HasRiskScore`. `DevicePosture` is a closed typed struct: `{Compliant bool, DiskEncrypted bool, OSPatchLevel PatchTier, AgentPresent bool, HasPosture bool}`. `HasPosture`/`HasRiskScore` distinguish "not computed" from "computed and fine" — the D28 rule that absent enrichment must fail explicitly, never default (a defaulted "compliant" is a silent fail-open).
- **Resolution:** the gateway's `ResolveContext` hook (D53 seam — the *same* hook peer-UEBA uses) resolves `{identity, role, device_posture, risk}` before dispatch. Device posture comes from the **endpoint agent's own enrolled identity (D44)**: the agent already has an Ed25519 identity and reports heartbeats (D42/D50); extend the heartbeat/telemetry to carry signed posture facts, which the control plane publishes and the gateway reads as context (T2, §5.5). This closes the loop *through context*, not through server commands.
- **Policy:** `internal/policy/mapping.go` `buildInput` exposes `input.context.{identity, role, device_posture, risk_score}` (extending the existing `input.context.risk_score`/`has_risk_score`, D53). Rules become identity-aware: `allow finance-group → payroll-api if device_posture.compliant`. The OPA restriction (D34, no network/clock/rand) is unchanged — an identity-aware policy still cannot phone home.
- **Fitness:** X (typed context via the D53 seam) — the roadmap's A2, "additive, the seam exists." **This is the crux reuse: identity-aware ZT authorization is the *same mechanism* peer-UEBA risk uses.**

### 5.4 Per-request/per-service authorization + microsegmentation (internal-service catalog)

- **New package `internal/gateway/catalog`** — the internal-service catalog: which services exist, and (as OPA policy, D34) which `{identity, role}` may reach which service under which posture. This is **identity-based microsegmentation** replacing IP-based ACLs (D84's "not IP-based" requirement): the authorization decision is `{identity, role, device_posture, risk} × service → ALLOW/BLOCK/REDIRECT`, evaluated per request through the *unchanged* pipeline. A denied access is `flow_id`→block (D73); a step-up-required access is `REDIRECT` to an auth challenge (the existing `ACTION_REDIRECT`, D69 — no new verb needed for step-up-via-redirect).
- **Fitness:** the catalog is policy data (like the §1.3 rule bundles) + the existing pipeline. No new core. The one *possible* new verb is §5.5.

### 5.5 Continuous verification loop — risk → step-up/deny (the T2 model)

- **The loop (T2, closing the D54 dead-end):** the control plane's peer-UEBA/correlation (§4.2) **computes and publishes** a risk score per subject; the gateway **reads it as context** (§5.3, the D53 seam) and the *local* policy decides. The server informs; it never actuates (D14/D54). A subject whose risk crosses a threshold mid-session gets `REDIRECT` (step-up auth) or `BLOCK` (deny) **by the gateway's local policy**, not by a server command.
- **Publishing risk:** a new `internal/controlplane/riskpub` — the control plane publishes per-subject risk on a signed subject the gateway subscribes to (reuse the signed-telemetry transport, D50, in reverse: server→gateway). The gateway resolves it into `Context.RiskScore` (already exists, D53). **[T2-FLAG]:** if the owner chooses to let the *server* actuate (reject T2), this becomes a server-issued command channel — which *reintroduces the exact D14 threat* (a compromised control plane commanding endpoints). The T2 model (server publishes, endpoint decides) is what preserves D14 while enabling ZT. This is the single most important flag in the document.
- **Optional new verb `ACTION_STEP_UP = 12`:** if `REDIRECT`-to-challenge is too coarse (REDIRECT is a coaching bounce, D69), a distinct `STEP_UP` verb means "require re-authentication before this flow proceeds," enforcer `internal/enforcers/flow` extended (target = `flow_id`, disposition = challenge). **D14:** typed, parameter-free ("challenge this flow"), cannot express exfiltration. **[T1-FLAG]:** whether ZT needs a dedicated `STEP_UP` or `REDIRECT` suffices is a one-verb T1 decision; the roadmap (A3) flags it as "maybe one A."
- **Fitness:** X (risk context) + at most one deliberate A. The whole ZT capability reuses D28/D53/D60/D69/D73/D75/D82 — the genuinely new code is the identity producer (§5.2), the posture context (§5.3), the access-proxy mode (§5.1), and the service catalog (§5.4). Everything else is existing seams.

---

## 6. Cross-cutting

### 6.1 Consolidated new proto / contract additions

All additive, all following the D69 pattern (a new `oneof` arm / enum member + its guard edit); **none edits the `Dispatcher`, `State`, `Stage`, `Enforcer`, `OnOutcome`, or the ledger**:

| Contract | Addition | For | D-shape |
|---|---|---|---|
| `EventKind` | `PROCESS_EXEC=8`, `DNS_QUERY=11` (`NETWORK_FLOW`/`HTTP_REQUEST` already exist) | HIPS, NDR | Additive enum (D69) |
| `Event.target oneof` | `ProcessSubject` variant (exec_path, pid, ppid, uid_pseudonym, cmdline_hash — metadata only) | HIPS | New oneof arm beside filesystem/usb/network (D69/D29) |
| `NetworkSubject` fields | `qname`, `qtype`, `nxdomain_ratio` (DNS); byte/timing counters (L4) | NDR | Additive fields (D69), metadata only (D10) |
| `DetectorType` | secrets, health, IBAN, passport, keyword, dns-exfil, signature members | DLP/NDR depth | Additive, type+conf+count only (D33/D10) |
| `ClassifyRequest.subject` | reuses existing `content` inline variant (D72) for gateway/response/multipart | DLP/NDR | Already exists |
| `core.Context` | `Identity`, `Role`, `DevicePosture{...,HasPosture}`, `ProcessLineage []LineageHop` | ZT, HIPS | Closed typed set (D28), via D53 hook |
| `policy input` | `input.context.{identity, role, device_posture, process_lineage}` | ZT, HIPS | `buildInput` additive (D53) |

### 6.2 Consolidated new Action verbs (each with its D14 justification)

Each is a **distinct, typed, parameter-free** enum member with its own enforcer and `schema_test.go`/`validate.go`/`mapping.go` guard edits. The closed-set property holds because **every verb can only *withhold or contain*, never *invoke* — none can carry a URL, path, or command** (the D14 red line):

| Verb | Meaning | Enforcer (`internal/enforcers/…`) | Target | D14 / T-flag |
|---|---|---|---|---|
| `DENY_OPEN=7` | `FAN_DENY` a pending file-open | `denyopen` (Targeted) | fanotify fd | Inline file prevention; DoS at worst. **[T1]** |
| `DENY_EXEC=9` | `FAN_DENY` a pending exec | `denyexec` (Targeted) | exec perm fd | HIPS prevent; withholds only. **[T1]** |
| `KILL_PROCESS=10` | `SIGKILL` a running pid | `killproc` (Targeted) | pid | Strongest verb; the T1 stop-line. **[T1/T2]** |
| `STEP_UP=12` (optional) | Require re-auth for a flow | `flow` (extended) | flow_id | ZT continuous verification. **[T1]** |

`REDIRECT=6`, `BLOCK=3`, `QUARANTINE_LOCAL=4`, `ENCRYPT_LOCAL=5`, `ALERT=2`, `ALLOW=1` already exist and are reused (ZT step-up via `REDIRECT`, NDR block via `BLOCK`+flow enforcer, DLP contain via `QUARANTINE_LOCAL`/`ENCRYPT_LOCAL`).

### 6.3 Sequencing / dependency graph

Following the roadmap's leverage-per-risk order, with dependencies made explicit:

```
Phase A — Identity & ZT (§5)  ← reuses D28/D53/D60/D69/D73/D75/D82; needs riskpub (§4.2 seed)
   │  identity producer (§5.2) ─┬─→ device-posture context (§5.3) ─→ service catalog (§5.4)
   │  access-proxy mode (§5.1) ─┘                                    └─→ continuous verify (§5.5, T2)
   ▼
Phase B — Inline prevention (§1.1)  ← needs A's identity context ("whose open to deny")
   │  prefilter (§1.1) + watchdog activation → DENY_OPEN (§1.1.1)
   ▼
Phase D — Detection depth (§1.2, §3.3)  ← independent; highest DLP-credibility payoff
   │  format parsers + detectors (§1.2) → admin-authorable signed bundles (§1.3)
   ▼
Phase C — Network breadth (§3)  ← transparent connector (§3.1) removes proxy-config limit
   │  non-HTTP producers (§3.2) + response/multipart (§3.3) + IDS plugin (§3.4)
   ▼
Phase F — SIEM depth (§4)  ← builds on D82/D83; correlation generalises peerueba
   │  search API → correlation+HA state → casework/four-eyes → UI → syslog ingest
   ▼
Phase E — HIPS (§2)  ← the T3 XDR fork; only on the platform bet
   │  exec producer → behavior classifier → DENY_EXEC/KILL_PROCESS → FIM
Cross-platform (§1.4)  ← runs in PARALLEL, E-gated (EV cert / ES entitlement, D9)
```

Hard dependencies: B depends on A (identity to decide *whose* action). §5.5 depends on §4.2 (risk to publish). §1.3 depends on §1.2 (detectors to author) and reuses D15 signing. Everything depends on the frozen core and the D53 context seam.

### 6.4 Where the frozen core WOULD be pressured — and how each is avoided or bounded

Honest accounting of every place a capability *pushes* on the core, per the D26/D69 "green CI is necessary not sufficient" discipline:

1. **New action verbs (§6.2)** — the *only* deliberate, bounded core-shaped changes. Each edits the `Action` enum + `validate.go` + `mapping.go` + `schema_test.go`. This is D14's designed speed-bump, not a violation: adding a verb is never silent (D69 precedent). **Bounded by:** one verb at a time, each parameter-free, each reviewed on its merits (T1). **[T1-FLAG]** governs whether they are added at all.
2. **New `oneof target` variants + `EventKind` (§6.1)** — additive proto, the exact D69 shape (`NetworkSubject` did this). **Avoided-as-a-real-change** because a new `oneof` arm is additive and the dispatcher switches on it generically; `State`/`Stage`/`Enforcer` are untouched.
3. **New `Context` fields (§5.3, §2.2)** — the D53 seam was *built for this* (identity/risk/lineage flow through `ResolveContext`). The pressure D53 already absorbed: `Context` is a **closed typed set, not a map** (D28) — so each field is a deliberate schema edit, which is the point, not a leak. **Bounded by:** the D28 no-open-bag rule; the pressure is "add a typed field," reviewed like an action.
4. **Stateful/cross-entity capabilities (lineage §2.2, DNS-exfil §3.2, correlation §4.2)** — the peer-UEBA new-shape (D53). **Avoided** by the D54 discipline: state lives *outside* core (in `internal/analytics`) and is resolved *into* `Context` via the hook — never accumulated inside a `Stage`. The fitness test's known gameable move (D26: letting policy query the analytics store directly) is the thing to keep banning; `check-capability-boundary.sh` extends to the new analytics packages.
5. **The T2 risk-publish channel (§5.5)** — the place the core is *most* pressured, because a server→endpoint channel looks like the D14 command channel. **Bounded by T2:** the server publishes *data* (a risk score) into `Context`; the endpoint *decides*. If T2 is rejected and the server actuates, **this becomes a genuine core-integrity violation** (D14) — flagged as the design's load-bearing assumption.
6. **Inline classification timing (§1.1)** — pressures the permission-window budget (D24/T-002), the reason D49 deferred inline. **Avoided** by *not* classifying in the window: the prefilter answers cheaply and the full classifier stays async (D49's own logic, now layered). The watchdog (D18) is the safety net, not the core.
7. **Cross-platform producers/enforcers (§1.4)** — **zero core pressure** by construction (D8): the core is portable Go; only the OS hook and enforcement syscall are per-OS, and they implement the *existing* connector/enforcer contracts.

**The single rule that holds throughout:** if any phase forces a change to `Dispatcher.dispatch`, `State`, the `Stage`/`Enforcer` interfaces, `OnOutcome`, or the ledger — stop and re-examine (roadmap "What stays frozen"). Every capability above lands in a **producer, a classify plugin, a typed context field, a connector/data-plane, or one deliberate action verb** — and nowhere else.

### 6.5 Honest cost/risk summary

- **Cheapest, highest-leverage:** ZT identity (§5) — mostly seam reuse (D60/D53/D69/D73), unblocks the sharpest overclaim (D84). But the identity producer + OIDC verifier + device-posture pipeline is real auth-layer engineering, not a plugin.
- **Highest DLP payoff:** detection depth (§1.2) — pure classify plugins in a sandbox that *already exists* (D35), earning back the cost of the privilege split (D13/D29).
- **Biggest credibility fix:** inline prevention (§1.1) — but it needs a new privileged code path (prefilter + activated watchdog) and a new verb; the failure mode (fail-open under load, D17) must be exercised for real (D18).
- **Largest scope risk:** HIPS (§2) and SIEM-as-a-product (§4.5) — the T3 XDR fork. Each is a subsystem with its own detection content; the roadmap's recommendation (DLP-deep first) is the disciplined call.
- **The load-bearing assumption:** T2 (server informs, endpoint decides). It is what lets ZT continuous verification (§5.5) and HIPS (§2.3) exist *without* reopening the D14 control-plane-actuates threat. Reject T2 and the entire "the server coordinates, it does not control" identity of the project is compromised.

---

**One-line fitness verdict:** every capability above is P/C/X/A/D-shaped (roadmap lens); the core changes reduce to a handful of additive proto members and a small, named set of deliberate action verbs — the D26/D69 claim ("a new *shape* needs a small, identifiable core change; nothing more") holding across DLP-deep, HIPS, NIPS/NDR, SIEM, and Zero-Trust, exactly as it held for the network gateway (D69) and peer-UEBA (D53).
