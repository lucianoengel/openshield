# OpenShield architecture roadmap

> Companion to [`decisions.md`](decisions.md). This file holds the **forward plan**: what
> OpenShield is today, the **MVP cut** (everything required before the UI), the **enrichment
> backlog** (post-MVP plugins on the frozen core), and the **design rationale** as reference.
>
> **Authoritative status is this file at `HEAD`, current through D419.** History (round-by-round
> audits, the R34 findings, per-ticket shipment notes) lives in git and the session memory — it is
> not re-carried here. The compact *Done ledger* below records what shipped so it is not
> re-proposed; open git log for the detail behind any `D<n>`.
>
> Architectural decisions are registered in [`decisions.md`](decisions.md); from D305 most `D<n>`
> handles are commit handles whose detail is the commit body. The assurance narrative — coverage
> rounds, and the running log of things that looked finished and were not — is
> [`unwired-audit.md`](unwired-audit.md).

---

## How the builder consumes this

- **The MVP line governs.** Everything under *MVP infrastructure* is required before the UI starts.
  Everything under *Enrichment backlog* is a post-MVP plugin that lands on the frozen core without
  gating the MVP. Work the MVP queue top-to-bottom; pull enrichment only when a lane is genuinely
  blocked or the owner redirects.
- **Re-verify before proposing.** The repo moves fast. Open the cited files at `HEAD` and confirm
  the gap still exists before starting a ticket. Treat `file:symbol` as the anchor; line numbers drift.
- **One OpenSpec change per ticket** (`openspec-propose` → implement → `openspec-archive`). Ticket
  IDs (`XDR-4`, `SOAR-4`, `PLAT-6`…) are stable handles — use them in the change name and commit.
- **Every acceptance test must drive the REAL runtime path**, never a mock built from the code's own
  assumptions. This project's signature failure is *"verifies against its own assumptions"* — a test
  that passes because it shares the code's wrong premise. For each negative security property, add the
  **mutation that would let the bug through** and prove the test catches it.
- **The frozen core governs.** If a ticket seems to force a change to `core.Dispatcher` / `State` /
  `Stage` / `Registry` / the `Enforcer` interfaces / `OnOutcome` / the ledger / the D10/D29 content
  boundary, STOP and re-run the D26/D69 fitness reasoning — capability lands as a producer, classify
  plugin, typed context, or one deliberate action, not a core change. See *Reference* below.

---

## What OpenShield is (status at a glance, through D426)

**OpenShield is architected as a pipeline-native XDR + SOAR** — one
Event→Classify→Policy→Decision→Enforce→Audit pipeline spanning **endpoint, network, and identity**, with
correlation, case/incident workflow, and a tamper-evident hash-chained evidence ledger above it. DLP is
one detection domain, not the center of gravity. The per-domain detection planes are now broadly real
and deep in several domains (hardware attestation, EDM/IDM, threat-intel + content-signature IPS, the
full HIPS-4 endpoint-behavioral suite, transparent inline network prevention). **The MVP infrastructure
queue below is now COMPLETE.** Cross-domain correlation, SOAR orchestration with live coordinated
response, the ZTNA client, the endpoint exfil channels, durable ingest, typed configuration, signed
reproducible releases and the operational lifecycle have all shipped and are tested. The only 🟡 left in
the queue is PLAT-6's remaining distribution work (Sigstore/cosign, `.deb`/`.rpm`, macOS notarization),
and each of those is a separate trust-or-distribution decision rather than leftover engineering.
**So PLAT-1 — the UI — is unblocked, and is the next thing.** It was deliberately last so it would be
built over a proven, tested, stable backend; that condition is now met.

**Why OpenShield, in one sentence (a thesis the MVP must *earn* — not yet a proven claim):** *every
security decision — detection, correlation, and response — is explainable, reproducible, and
cryptographically auditable, on one incident timeline across endpoint, network, and identity.* Lead with
that; "pipeline-native XDR" is the engineering, not the pitch. Product positioning is currently thin — a
named gap, but an owner/README messaging task (it needs the product's voice, not a builder's), deliberately
NOT an infra ticket and not part of the queues below.

| Category | Maturity | One-line reality |
|---|---|---|
| **XDR** (umbrella) | ~80% | Entity graph WIRED and populated by real producers (device⋈user, D203); the entity-keyed `unified_alerts` stream is fed by **every** domain (D213/D241); and it is now **correlated cross-domain** — a distinct-domain window rule + an ordered domain-sequence rule grouped by `entity_id`, severity boosted per domain, materialized per entity and paging once (D242). incidents now carry a cross-domain **timeline** — contributing alerts in detection order, each linked to its evidence with an explicit resolved/unresolved/derived state, and reading one is view-audited (D243). Coordinated cross-domain response (XDR-6, D254) and per-entity risk aggregation (XDR-7, D255) both landed — **Lane A is complete.** **Remaining gap is the operator surface:** there is no analyst UI to read a timeline in, and the CLI/API are the interface (PLAT-1, parked and deliberately last). |
| Zero Trust (ZTNA) | ~85% | Full hardware attestation chain (ZT-1, swtpm-proven end-to-end: TPM quote → EK→AK activation → measured-boot PCR → continuous re-attestation → network self-enrollment; EK-cert anchor + pre-auth enroll token + attestation TTL + DPoP-bound tokens). Live JWKS refresher, RBAC tiers, dual-credential access proxy. The endpoint half now exists: an agent-brokered client presents the DEVICE certificate to the access proxy, refuses to start without an identity, binds loopback only and never falls back (ZT-4, D249). **Residual:** it brokers access but does not yet PREVENT bypass (routing/firewall enforcement over the NIPS-1 plane is a separate ticket); HTTP(S) only, no CONNECT/SOCKS, no split DNS. |
| DLP | ~78% | Deep content detection: EDM single/multi-cell + IDM doc-fingerprint + exfil-channel awareness + keyword-proximity + national IDs, all boundary-honored; signed indexes (ADR-9); recursive archive extraction; content-aware CASB blocks sensitive uploads to unsanctioned clouds. Clipboard is now MEDIATED on X11 — the engine owns the selection and DECIDES each paste per destination (source→destination, enforced, VM-proven with a real cross-process paste refused), with password-manager exclusions applied before the read (D246/D247). Wayland stays observe-only: its protocol cannot identify a paste's destination. PRINT is intercepted in the CUPS filter chain and a sensitive job is ABORTED before it prints (DLP-2b, D248, proven on a real spooler). **Lane E DLP work is complete for the MVP.** **Enrichment:** OCR, screenshot, CASB refinements. |
| NIPS / NTPS | ~60% | Real inline IPS: transparent TPROXY drops/splices L4 by dst-IP/SNI/payload and self-installs + self-heals its rules (VM-proven); threat-intel IOC engine + content-signature engine (hot-reload, local file or remote URL); DNS preventive sinkhole with transparent :53 redirect (local + forwarded) + bypass watchdog (VM-proven). **Enrichment gap:** full Suricata grammar, HTTP/2/QUIC, JA3, SMTP filtering. |
| SIEM | ~52% | Alert lifecycle unified (severity/status/dedup, ATT&CK mapping, durable notify dedup, pruned baselines); external-log ingest live (CEF-syslog + AWS CloudTrail + WEF Windows-XML) with field-level JSONB hunting via `GET /logs`. **Enrichment gap:** more formats, saved searches, cross-vendor field normalization. |
| HIPS | ~85% | Full HIPS-4 suite shipped + inline exec PREVENTION on a live kernel: static `DENY_EXEC` (deny-list/whitelist) + `FAN_OPEN_EXEC_PERM` producer + default-deny whitelisting (VM-proven); FIM (baseline/real-time/signed/delete), ransomware canary, memory-injection detection; trusted-identity critical-process guard + pid-reuse revalidation. The exec gate now gets its verdict from the FULL PIPELINE over a parser-free IPC bridge, VM-proven (D244, inc 2a). The intent-driven half is DONE too: a `CONTAIN` Response-Intent makes the entity's next exec kernel-REFUSED via a real OPA policy, VM-proven (D253). **The endpoint half of coordinated response is complete.** **Enrichment:** eBPF/LSM real-time hooks, JIT W+X allowlist, per-process ransomware attribution. |
| **SOAR** | ~95% | A case+notify shell with the notify gap closed (SOAR-1, D220: a materialized incident pages once, automatically). Correlation runs on a CLOCK (leader-only) and incidents carry a forward-only attributed lifecycle open→acknowledged→triaged→contained→closed (SOAR-2, D250). The control plane now ACTS: a declarative playbook over a closed, non-actuating step registry runs first response automatically and resumes across a restart without duplicating a step (SOAR-4, D256). Threat intel is real: signed feed ingest into a shared IOC store, and incidents are enriched from observables the verified events already carry (SOAR-5, D257). Response time is measured — detection latency, MTTA and MTTR, each reported with the population it excludes (SOAR-6, D258) — and notifications are ROUTED by kind/severity to named sinks, with a pending approval finally paging a human (SOAR-9, D259). An approved intent is ENACTED against an external identity provider with four-eyes re-checked by the runner (SOAR-8b, D260), and incidents sync bidirectionally with a ticketing system (SOAR-8a, D261). **LANE B IS COMPLETE.** |
| NAC · VPN | 0% | Absent; off-pipeline. **Parked** (ADR-0). Not in the headline category set. |

**Crown jewel (protect it):** the per-agent forward-secure hash-chained ledger + external anchoring is
real end-to-end and is the platform's strongest asset. Do not regress it.

---

## The MVP cut

**MVP = a coherent, deployable, correlated XDR + SOAR with live coordinated response** — not a bag of
detectors. Concretely, the MVP is reached when:

1. **Every domain's detections land in one entity-keyed alert stream and correlate cross-domain** into
   one incident per attack, with a tamper-evident timeline (XDR lane).
2. **Incidents drive automated orchestration** — scheduled correlation, playbooks over a closed step
   registry, four-eyes approvals, enrichment, and metrics — and **live containment** flows through the
   signed Response-Intent seam and off-pipeline integration runners (SOAR lane, ADR-12 all three tiers).
3. **Containment actually bites on the endpoint:** a `CONTAIN` intent PREVENTS the entity's new execs
   inline (policy evaluated at the exec gate), not merely kills them after they run (Endpoint lane).
4. **The DLP domain watches the channels users exfiltrate through** — endpoint clipboard and print, not
   only file writes + cloud upload (Endpoint lane).
5. **A ZTNA client (ZT-4)** closes the identity story, and **the platform is production-shaped:** durable
   ingest is the default, config is typed and validated, there is a signed, packaged, deployable release,
   and it can be **upgraded, backed up + restored, and emergency-disabled** (operational lifecycle —
   Platform lane). MVP is **Linux-first**; Windows/macOS is enrichment.

**Then, and only then, the UI** (PLAT-1) — it is deliberately last, built over a proven, tested,
stable backend.

Everything else — richer detectors, OCR, more file formats and protocols, more countries, more log
sources, richer NIPS grammar, screenshot capture, cross-platform Windows/macOS, SAML — is **enrichment**:
additive producers and classify plugins on the frozen core. None of it gates the MVP; it lands
opportunistically or after the UI.

---

## ✅ MVP infrastructure — the required queue (COMPLETE)

**Every ticket in the five lanes below has shipped.** Lanes A (XDR), B (SOAR), C (Zero Trust), D
(Platform) and E (Endpoint) are closed; the sole remaining 🟡 is PLAT-6's distribution work, which is a
set of named trust/distribution decisions, not engineering left undone. The section is kept — rather than
collapsed into the Done ledger — because each entry states the **residuals** its ticket deliberately did
not close, and those residuals are the honest boundary of what the MVP claims.

**Do not re-propose anything here. The next work is Lane F · Console (PLAT-1, now decomposed and
unparked), plus enrichment.** Start at `CONSOLE-1` — and read its preamble first: it is not a UI ticket, it
is a shipped ZT-7 defect that makes SSO operators unable to acknowledge, transition, or read a timeline,
and whose naive fix collapses four-eyes.

Each ticket names the ADR it implements where one applies, and its `Accept` is the real-path test that
closed it.

### Lane A · XDR — cross-domain correlation & coordinated response

The headline. Turns per-domain alerts into one correlated incident with a tamper-evident timeline and
one-approval containment. **Spine: XDR-2 → XDR-4 → XDR-5 → (XDR-6 w/ SOAR-7) → XDR-7.**
(XDR-1 entity graph + XDR-3 subject stamping already shipped — see Done ledger.)

- **XDR-2 · Cross-domain alert normalization** — ✅ **DONE (D213 inc 1, D241 inc 2)** — see Done ledger.
  Increment 2 wired every remaining domain by projecting each VERIFIED non-`ALLOW` `Decision` at ingest,
  so DLP, HIPS, network/DNS/SMTP and the ZT access proxy all write the unified table. *Residual, NOT
  gating XDR-4:* a detection that never reaches a decision is not projected, and the domain label is a
  coarse grouping hint (ZT denials land under `nips`; giving ZT its own domain needs the Event to
  distinguish access from egress — a contract change deliberately not made for a label).
- **XDR-4 · Cross-domain correlation rules** — ✅ **DONE (D242)** — see Done ledger. `CorrelateCrossDomain`
  groups `unified_alerts` by **`entity_id`** (never a subject string) with a distinct-domain window rule +
  an ORDERED domain-sequence rule, severity boosted per domain, materialized per entity and paging once;
  `GET /incidents?rule=cross_domain` selects it, default unchanged. *Residual, NOT gating XDR-5:* the
  sequence vocabulary is **domains, not ATT&CK techniques** — `internal/attack` techniques are Rego policy
  INPUT (`internal/policy/mapping.go`) and are never persisted on an alert, so technique-level sequences
  need a `Decision` contract change. Named, not faked. No alert-storm suppression; no retro-correlation
  outside the window.
- **XDR-5 · Incident timeline** — ✅ **DONE (D243)** — see Done ledger. `incident_alerts` join +
  `unified_alerts.event_id`/`.decision_id` evidence references + `incidents.domains[]`;
  `IncidentTimeline` orders by `detected_at` and resolves evidence against `audit_entries` in three
  honest states (`resolved` with ledger coordinates / `unresolved` with the reference intact /
  `derived` for a server-side alert); `GET /incidents/timeline?id=N` is analyst-tier and records the view.
  *Residual, NOT gating XDR-6:* no backfill for pre-existing alerts/incidents; the timeline reports ledger
  COORDINATES and does not verify the chain (the anchor binary owns that); no timeline for `ueba_burst`
  incidents (explicit 409, never an empty list); `unified_alerts` retention must eventually cascade to the
  join — a retention-ticket item.
- **XDR-6 · Coordinated cross-domain response** — ✅ **DONE (D254)** — see Done ledger. One signed,
  four-eyes-approved CONTAIN → gateway BLOCKs the entity's flows and the endpoint DENIES its execs, each by
  its own local policy, both stamping the SAME intent id via `Context.Version` (the D27 field already
  carried to the ledger — no hashed-column change). TTL expiry restores both. *Residual:* a policy that does
  not read `response_intent` is unaffected (data-not-command); the exec gate still fails open; an entity
  that never crosses the gateway is not blocked by it.
- **XDR-7 · Entity risk aggregation** — ✅ **DONE (D255)** — see Done ledger. MAX-not-sum over every
  domain's alerts, recency-weighted, published to EVERY alias of the entity; `RiskStore` raises but never
  lowers. Proven over real signed pub/sub: a HIPS detection on a device raised the USER-keyed risk to 0.885.
  *Residual:* a heuristic, not a calibrated probability; stepwise on the correlation interval; sticky
  (no decay until a later ticket).

### Lane B · SOAR — orchestration & automated response (ADR-12)

The other headline. All three ADR-12 tiers are owner-approved. **Spine: SOAR-2 → SOAR-3 → SOAR-4 →
(SOAR-5, SOAR-7) → SOAR-8.** (SOAR-1 incident→notify shipped, D220.)

- **SOAR-2 · Scheduled correlation + escalation** — ✅ **DONE (D250)** — see Done ledger. `RunCorrelationLoop`
  materializes both rules on a ticker inside the LEADER's context; incidents gain a forward-only attributed
  lifecycle + `POST /incidents/transition`. *Residual:* it raises and pages, it does not ACT (SOAR-4/5/7/8);
  no escalation timers (SOAR-9 shipped routing, not schedules); no reopen; no backfill outside the window.
- **SOAR-3 · Generic four-eyes approval object** — ✅ **DONE (D251)** — see Done ledger. An `approvals`
  table keyed by (subject_kind, subject_id); every condition in the UPDATE predicate so resolution is
  atomic; expiry enforced in the predicate; one pending approval per subject; case closure rewired onto it.
  *Residual:* no approval POLICY and no N-of-M (the caller decides). A pending request now NOTIFIES
  (SOAR-9/D259), and SOAR-4's `wait-for-approval` plus SOAR-7's intents are live consumers — the
  "one caller" residual is closed.
- **SOAR-4 · Playbook engine v1 (server-side only)** — ✅ **DONE (D256)** — see Done ledger. A trigger
  (severity floor / kinds / domains) plus an ORDERED LIST of steps from a closed registry refused at LOAD;
  durable resumable run state whose already-done guard lives in the SQL claim; `wait-for-approval` is the
  approvals object's first automation consumer; leader-only. *Residual, named:* **no actuation** (Tier-1 by
  construction — SOAR-7/8 own that); no DAG, no retries/backoff, no rate limit on playbook starts;
  `enrich` is local context assembly, not threat intel (SOAR-5); the approval gate is a one-operator
  human-in-the-loop gate, NOT two-human four-eyes, because the requester is the playbook.
- **SOAR-5 · Enrichment + threat-intel** — ✅ **DONE, increment 1 (D257)** — see Done ledger. Detached
  ed25519 feed verification that runs BEFORE the parser (asserted by a parser-entry counter, not by the
  refusal alone); a `ioc_indicators`/`ioc_feeds` store with snapshot-replace semantics; ONE matcher shared
  with the inline NIPS engine; enrichment walking XDR-5's evidence references to observables the verified
  events already carry. *Residual, named:* **no EPSS/KEV** (both key off a CVE id and nothing in the
  pipeline produces one); **no geo/ASN** (a licensed GeoIP data file — a distribution decision); **no
  STIX** (a large untrusted-JSON surface; an external converter is the right shape); no IOC ageing,
  confidence or TLP; no retro-hunt when a feed lands; no signed URL fetch; unsigned feeds still load when
  no key is configured (warned, not silent); and a hit ANNOTATES, never enforces.
- **SOAR-6 · MTTA/MTTR + analyst metrics** — ✅ **DONE (D258)** — see Done ledger. Three durations kept
  APART (detection latency = our lag, MTTA = the analyst's, MTTR = closed only), Prometheus histograms +
  `GET /report/response`, every average reported next to its EXCLUDED population. No migration — SOAR-2's
  forward-only lifecycle is what made `transitioned_at` readable as a closure time. Fixed a defect it
  surfaced: a transition straight to `triaged` never stamped `acknowledged_at`. *Residual, named:* **no
  per-analyst aggregation** (deliberate — that is workforce surveillance, and a test asserts no series
  names an operator); no SLA targets or breach alerting; no per-severity/domain split; contained-but-open
  is not counted as resolved; the aggregate is computed per scrape, not incrementally maintained.
- **SOAR-7 · Response-Intent seam (Tier-2)** — ✅ **DONE (D252)** — see Done ledger. Closed 3-verb signed
  TTL'd `ResponseIntent`; publication gated on four-eyes (bound to the intent id) + a blast-radius ceiling
  refused as a whole; consumed as VERIFIED policy context with expiry evaluated on read. **This unblocks
  XDR-6 and HIPS-3 inc 2b** — both now need only their enactment half. *Residual:* nothing enacts intents
  yet; a consumer that ignores them is unaffected by design; signing proves origin, not authority.
- **SOAR-8 · Integration runners v1 (Tier-3)** — ✅ **DONE — (b) D260, (a) D261.**
  (b) The IdP responder ships: an intent subscriber with a per-connector CLOSED verb set, four-eyes
  required for EVERY verb and re-checked by the runner, at-most-once claim, and a durable
  intent-id→API-call record (the intent id also rides an `X-OpenShield-Intent` header so a receiver's
  access log alone links the call to what authorized it). **This is the first OpenShield action that
  cannot be undone — expiry restores nothing here**, unlike every other intent enactment.
  *Residual, named:* no vendor API shapes (a generic authenticated JSON connector; a vendor adapter is a
  per-vendor addition); no retries (an automatic retry of an irreversible call is how one failure becomes
  several); no rollback of a partially-applied multi-action verb; the subject crosses as the PSEUDONYM
  and the deployer's receiver must do the pseudonym→account join.
  (a) ITSM sync ships (D261): one ticket per incident, a CLOSED set of remote statuses that mean closed
  (anything else is ignored, never assumed closed), sync-back attributed to the connector — and
  forward-only survives, so a reopened ticket does NOT reopen its incident. It gets its OWN table, because
  a ticket is mutable/retryable/bidirectional while `runner_actions` records irreversible at-most-once
  acts, and sharing would weaken the stronger guarantee. *Residual, named:* **polling, not a webhook**
  (sync-back lags one interval; a webhook needs an inbound route a SaaS can reach — a separate decision);
  no vendor API shapes; only `closed` is synced (mapping intermediate states would corrupt SOAR-6's
  metrics); no comment/worklog sync or post-creation field updates.
- **SOAR-9 · Notification routing/templating** — ✅ **DONE (D259)** — see Done ledger. An ordered
  kind/severity → named-sink table with FIRST-MATCH-WINS (the only semantic that can express "critical to
  the pager ONLY"); an unmatched notification goes to every sink and is COUNTED, so a table with a hole
  over-notifies visibly rather than going silent. Also closes SOAR-3's residual: a pending approval now
  notifies, which is what makes SOAR-4's `wait-for-approval` a gate rather than a deadlock. *Residual,
  named:* **no templating** (an injection surface into whatever renders it; formatting belongs in the
  receiver); no escalation ladders, on-call schedules, rotations or reminders (they need a schedule model
  this does not have); no per-sink rate limiting or digesting; routing matches kind and severity ONLY —
  never a subject, which would be a re-identification surface and a way to route one person's alerts out
  of sight.

### Lane C · Zero Trust — the ZTNA client

- **ZT-4 · ZTNA client/connector model** — ✅ **DONE (D249)** — see Done ledger. `internal/ztna` brokers
  application traffic to the access proxy over device-cert mTLS. *Residual, named:* it brokers but does not
  PREVENT bypass (routing/firewall over the NIPS-1 plane is a separate ticket), HTTP(S) only (no
  CONNECT/SOCKS for SSH/RDP/databases), and no split DNS.

### Lane D · Platform — durability, config, packaging, operability

- **PLAT-2 · Durable ingest by default** (ADR-2) — ✅ **DONE (D245)** — see Done ledger. Durable ingest is
  the default (opt-out `OPENSHIELD_JETSTREAM=0`), all THREE producers switch through one helper (before this,
  only the *simulator* was durable — the engine and gateway published at-most-once), and an unavailable
  JetStream fails fast on both producer and consumer rather than silently degrading. *Residual, honest:* not
  loss-free (unspooled-unpublished is gone; the stream's bounds still drop on a long outage), at-least-once
  not exactly-once, and the non-telemetry subjects stay core-NATS best-effort by design. **BREAKING:** a
  JetStream-less broker must enable it or opt out — a PLAT-9 runbook item.
- **PLAT-5 · Config management beyond env vars** — ✅ **DONE, server (D262 + D263)** — see Done ledger. Typed
  fields declared ONCE and used for both reading and describing, so the schema is derived rather than
  maintained beside the code — **because config will eventually be set mostly in the UI (PLAT-1), and a
  hand-written schema drifts silently from what the binary reads.** Secrets are a KIND and are never
  readable back (not in the schema, the effective output, the printed form, or a validation error);
  errors are field-scoped and all reported at once; sources are an interface, env → file → default.
  `openshield-server config` prints the effective values with their origin. **D263 then made the model
  enterprise-shaped:** every field declares a SCOPE — bootstrap (env/file, ~16 fields: reach-the-database
  settings) vs dynamic (**the database is the only source**, cluster-wide, ~33 fields) — with revisions
  carrying author/diff/rollback, validation at save, and LIVE APPLY (a watcher swaps an immutable
  snapshot; loops read parameters per tick). **Secrets are never stored**, so a config-DB dump is not a
  credential dump. *Residual, named:* no UI yet (this is the model and the API it will call); the
  ~~binaries still using the old helpers~~ — **ALL binaries now declare their configuration (D274)**; a
  whole-tree guard reads `cmd/` so a new one cannot be missed. The GATEWAY (D272) and
  the privileged AGENT + sandboxed WORKER (D273) adopted the package; the latter proves it works at the
  tightest boundary, being stdlib-only so the agent's dependency ban and the worker's seccomp filter both
  still hold. The gateway is declared
  ALL-BOOTSTRAP because a network appliance's settings are node-local, so it needs no database
  credentials and a future fleet-wide gateway setting belongs on the signed channel; no per-node dynamic
  values; no staged rollout; no keystore.
  **BREAKING:** a dynamic field set in the environment no longer takes effect — it is reported, not
  silent (`OPENSHIELD_BREAKGLASS` is the deliberate, reported override).
- **PLAT-6 · Release, packaging & deploy** — 🟡 **increment 1 DONE (D264)** — see Done ledger. `make
  release` builds every command reproducibly (`-trimpath`, `CGO_ENABLED=0`, `-buildvcs=false`) and emits a
  SHA-256 manifest signed with a detached ed25519 signature; `make verify-release` re-checks every digest,
  the signature, and **files present that the manifest does not name**. Reproducibility is asserted by a
  test that builds twice, because without it a signature attests only that the signer had *a* binary.
  `deploy/` already carried the systemd/install path. **D276 adds a SIGNED SBOM** — written before the
  manifest so the signature covers it, and generated from the BINARIES (`debug/buildinfo`) so it describes
  what shipped rather than what go.mod intended. **D277 adds tag-triggered release automation** that VERIFIES and proves
  reproducibility before publishing. *Remaining:* Sigstore/cosign + transparency log, .deb/.rpm, macOS
  notarization — each a separate trust or distribution decision rather than leftover work. **goreleaser and Helm are REFUSED, not deferred** (D276):
  goreleaser would replace working tested code with a toolchain for conveniences not needed, and a Helm
  chart would contradict the compose/systemd footprint this project documents.
- **PLAT-9 · Operational lifecycle & recovery** — ✅ **DONE.** **emergency disable (D265), verified restore (D266)
  schema-skew reporting (D267), the RUNBOOK + footprint (D268), the ENDPOINT fleet-wide disable (D269),
  fleet acknowledgement (D270/D271), the wire-version contract + upgrade ORDER (D275) and the
  backup/restore DRILL + node-recovery table (D277) all DONE, and the drill is now RUN end-to-end against
  real pg_dump/pg_restore with truncation detection proven (D278). **PLAT-9 is complete.**
  D269 closes the gap D265 named about itself: a signed `FleetControl` (its own two-verb vocabulary, NOT
  a fourth IntentVerb) bounded by a monotonic sequence (replay), a mandatory TTL (duration) and four-eyes
  on every disable. *Residual:* the control plane cannot CONFIRM a fleet is disabled — publication is
  best-effort and an agent offline past the TTL never applies it. **D270 closes the reporting half:** the
  heartbeat now carries each agent's ACTUAL enforcement state and applied sequence, so "how many are
  still enforcing?" is answerable — with the honest limit that SILENCE IS NOT COMPLIANCE (absence stays
  the overdue mechanism's job).
  D267 fixed a real rollback defect: `fullyMigrated`'s `applied >= want` let a rolled-back binary run
  SILENTLY against a newer schema. It now reports the skew (loudly, plus a gauge) and still STARTS —
  refusing would turn a rollback into an outage. Migrations are FORWARD-ONLY: rolling the BINARY back is
  supported, rolling the SCHEMA back is not.
  `openshieldctl restore-verify` is the post-restore gate: the witness key is MANDATORY and "I cannot
  tell" is a FAILURE, because a truncated ledger is internally CONSISTENT (it hashes perfectly and stops
  early) and only an anchor detects that. It reports the tail an anchor cannot cover, and separates
  verified / damaged / undetermined. *Residual:* it verifies, it does not back up or restore; anchor
  cadence bounds what completeness can prove.
  `core.KillSwitch` is consulted by BOTH enforcement call sites, sits between the Decision and the
  Enforcer (so detection and the ledger continue — stop acting, keep seeing), fails TOWARD enforcing (an
  unreadable source never disables the product), counts every suppression with its reason, and is engaged
  either by a local break-glass file or by a dynamic setting that propagates fleet-wide via PLAT-5b's
  watcher. *Residual, named:* the fleet path reaches only components that read the config store —
  **endpoint agents do not**, so their fleet-wide disable needs the signed channel (increment 2).
  **The original scope — and every part of it is now delivered**, kept here as the record of what the
  ticket promised: the question a CISO asks first is *how do I run this?*, and the roadmap once answered
  only "packaging." Delivered: rolling agent + server upgrade with version-skew tolerance and **rollback**
  (D275, and migrations are forward-only — rolling the BINARY back is supported, rolling the SCHEMA back
  is not); a fleet-wide **emergency disable** that fails toward enforcing and is itself ledgered (D265,
  D269); **backup + verified restore** of the Postgres system-of-record and the per-agent ledger, with the
  restore re-verifying the hash chain and anchors rather than only the bytes (D266, D277, D278); node/DB
  recovery and a DR runbook; and a documented **deployment footprint** — a compose/systemd product, not a
  50-node cluster, stated so operators can size it, and publishing **no** throughput figures because no
  load exercise has been run (D268, [`runbook.md`](runbook.md)). *Accept, met: an upgrade rolls forward
  and back with no ledger gap; a restored backup re-verifies its chain + anchors; emergency-disable flips
  the fleet to observe-only within one interval and writes a ledger entry.*

*(Cross-platform Windows/macOS observe is **enrichment**, not MVP — MVP is Linux-first; see the
enrichment backlog. Enforcement everywhere stays owner-gated per ADR-11.)*

### Lane E · Endpoint — enactment & exfil channels

Makes containment bite where the process runs, and makes the DLP domain watch the channels users
actually exfiltrate through (not just directories). Lane E's HIPS-3 inc 2 is a hard dependency of XDR-6.
(DLP-2 is split: 2a/2b clipboard+print are MVP here; screenshot + CASB refinements stay DLP-2 in enrichment.)

- **HIPS-3 increment 2a · The exec-gate IPC bridge** — ✅ **DONE (D244, VM-proven on kernel 6.8)** — see
  Done ledger. `internal/agent/execipc` is a parser-free hand-rolled transport (the privileged binary still
  carries no protobuf/`corev1`, now CI-enforced); the client is only a `watchdog.Evaluator`, so the existing
  budget/fail-open stays the single source of truth; hardening shipped and tested (verdict cache, per-path
  circuit breaker, deadline-aware connection lock, bounded in-flight). Five mutations verified failing,
  including "always allow" against the real kernel.
- **HIPS-3 increment 2b · Intent-driven inline `DENY_EXEC`** — ✅ **DONE (D253, VM-proven)** — see Done
  ledger. The intent is a CLOSED enum field on `core.Context`; the engine resolves it via the existing
  `ResolveContext` hook; a real OPA policy refuses a CONTAINed entity's exec with EPERM, and lifting the
  containment restores execution. *Residual:* a policy that does not read `response_intent` is unaffected
  (data-not-command), and the gate still fails open, so containment depends on a live engine.
- **DLP-2a · Clipboard exfil producer** — ✅ **DONE (D246)** — see Done ledger. `internal/clipboard` +
  `EVENT_KIND_CLIPBOARD_COPY` + `ChannelClipboard`; content goes to the sandboxed worker, the Event is
  content-free (proven on the serialized bytes), real X11 capture VM-proven under Xvfb. *Residual, honest:*
  POLLED (a copy replaced inside one interval is missed), TEXT ONLY, needs `wl-paste`/`xclip`, the engine
  holds the bytes in memory to forward them (same trade as the gateway's bodies), and it does NOT block a
  paste. Event-driven capture (XFIXES / `wl-paste --watch`) and Windows/macOS (PLAT-7) stay deferred.
- **DLP-2b · Print exfil producer** — ✅ **DONE (D248)** — see Done ledger. A CUPS filter decides the job
  before it prints (non-zero exit aborts it); the job is classified in the sandboxed worker; `PrintSubject`
  omits the title deliberately. Real-spooler proven. *Residual:* chain placement determines detection
  quality (text vs raster), only the head of a huge job is classified, no CUPS-bypassing paths, no
  watermark/redact, install is a root step.
*(Lane E's MVP items — HIPS-3 inc 2a/2b, DLP-2a, DLP-2b — are all ✅ above. **Lane E is complete**, and
with it the MVP queue.)*

---

## 🚧 Lane F · Console (PLAT-1) — the next queue

Design: `docs/superpowers/specs/2026-07-31-console-plat1-design.md` (adversarially reviewed against D426).
**PLAT-1 is roughly 40% backend**, and one part of it is a shipped defect that already breaks ZT-7 SSO.

**Read this before pulling anything here.** `requireTier` (`internal/controlplane/views.go:131`)
authenticates by client certificate **or** OIDC bearer token and then discards `auth.identity` — it never
reaches the request context. Eight handlers re-derive identity from `operatorIdentity(r.TLS)`
(`views.go:166`), which returns `""` without a peer certificate. **So an SSO operator today passes the tier
gate and is then refused by `/alerts/ack`, `/incidents/ack`, `/incidents/transition`,
`/incidents/timeline`, `/cases/*`, `/searches/save`, `/subject` and `/view`.** D373 shipped an
authentication method that reaches almost none of the product. Same shape as D415/D417/D418.

And the obvious fix is a trap: a certificate mints `"operator:" + CN`, a token mints the raw `sub`, and
four-eyes is `AND requester <> $2` (`internal/controlplane/approvals.go:119`). Thread the bearer identity
through unchanged and **one human requests from the CLI and approves from the browser** — two-person
control collapses on case closure, `CONTAIN` intents and fleet `ENFORCEMENT_DISABLE`. `CONSOLE-1` fixes
both as one change or neither.

### Phase 0 · Foundation

- **CONSOLE-1 · One canonical operator principal** — new work · L. Namespaced principals
  (`cert:<CN>` / `oidc:<iss>#<sub>`), threaded through `requireTier` onto the request context; the eight
  `operatorIdentity(r.TLS)` sites read from there; `operator_identities` links principals to one account
  and **four-eyes compares the account, not the string**; `operator_roles` gains an issuer discriminator so
  an IdP subject cannot inherit a certificate CommonName's row; the operator route set becomes **data** so
  a registered-but-unmounted route is unrepresentable, and `/report/response` (SOAR-6, registered at
  `operator_read.go:231`, absent from the outer mux) is mounted by it.
  `Accept`: a bearer-only operator acknowledges, transitions, reads a timeline and opens a case; and one
  human with two credentials is REFUSED at four-eyes, with the test first asserting the request reached the
  tier gate. *OpenSpec change proposed: `2026-07-31-console-1-operator-principal`.*
  **Three seams ride along, because this is the only cheap moment for them.** This ticket already rewrites
  the principal model, adds a table, and moves four-eyes from a string to an account. Each of the following
  is S-sized inside it and L-sized after it — after it they mean touching the same eight handlers, the same
  cursors and the same four-eyes predicate a *second* time, and this file's own §1 preamble is the record of
  what a second pass costs:
  - **A machine principal distinct from a human one** — `svc:<name>`, with its own issue/scope/expire/
    rotate/revoke lifecycle, and the non-negotiable rule that **a service account can NEVER satisfy
    four-eyes**. Without it every customer integrating a ticketing system or a script hands a robot a
    human's certificate, which is what the four-eyes account comparison is being built to detect.
  - **A scope predicate on the principal**, resolved in `requireTier` and carried in the pagination cursor,
    **defaulting to "all"**. This does NOT build multi-tenancy (still deferred, ADR-4, and named as an
    evaluation-ending gap at `docs/enterprise-gap-assessment.md` §3). It reserves the seam so tenancy is
    later a WHERE clause rather than a rewrite of every handler and every cursor.
  - **Split `admin` into `admin` and `privacy-officer`** for DSAR export, legal-hold release and the
    view-audit reader. Today one tier fuses "can change configuration" to "can read every subject's
    compiled personal data", and no SOC 2 / ISO 27001 access review is answerable with three tiers. Full
    per-capability custom roles stay deferred (`CONSOLE-30`); this is the separation of duties that cannot
    wait for them.
- **CONSOLE-2 · Toolchain, dependency budget, reproducible bundle** (ADR-13) — new work · M. React/TS/Vite
  under `apps/console/`, embedded via `embed.FS`, same origin, no CDN, Node-free `go build`. The budget is a
  **number** enforced in CI, and every direct dependency gets the one-sentence justification D276 demanded
  when it refused goreleaser as "a dependency taken for its own sake". `Accept`: pinned-digest network-less
  container build, `SOURCE_DATE_EPOCH`, and a byte-identical rebuild check that FAILS the release —
  `internal/release/release_test.go:161` already tests that Go builds are reproducible, and embedding
  bundler output puts a non-deterministic input inside that digest. Note `--ignore-scripts` is not the
  control: `vite.config.ts` and its plugin import closure execute with filesystem and network access during
  the build, on the machine holding the signing key.
- **CONSOLE-3 · Browser session auth** (ADR-14) — CONSOLE-1 · L. OIDC Authorization Code + PKCE, `state`
  bound to a pre-auth cookie, `nonce`, callback `iss` check; server-side session in a `__Host-` cookie
  (`HttpOnly`, `Secure`, `SameSite=Strict`, idle + absolute timeout); CSRF as an `X-OpenShield-CSRF`
  **header** so no existing route signature changes, plus an independent `Origin` check. The console's
  OAuth client is a **separate component from the bearer verifier**, and a token whose `aud` is the console
  `client_id` is refused on the bearer path. **`REQUIRE_DPOP=1` refuses console login and says so at
  startup** — a cookie has no proof-of-possession, and silently exempting the browser is the downgrade that
  switch exists to prevent. `Accept`: authorization is unchanged (no tier ever derived from a claim), and
  the mutation that makes the session carry a `groups` claim fails the test.

### Phase 1 · Slice 1 — one page, end to end

- **CONSOLE-4 · Incidents queue + timeline detail** — CONSOLE-1,3 · L. The riskiest unknowns proved on the
  real path before any framework generalization: session auth → `/incidents` → `/incidents/timeline` with
  the **three evidence states rendered visually distinct** (resolved / unresolved / derived) → the view
  recorded under the session principal. No i18n, no palette, no a11y gates yet. `Accept`: an analyst reads
  a cross-domain timeline and a derived evidence link is not mistakable for a resolved one.

### Phase 2 · The MVP console

- **CONSOLE-5 · View-audit repair + `investigation_views` retention** — CONSOLE-1 · M. **A console
  WEAKENS a documented trust boundary unless this lands.** `RecordView` has four call sites
  (`views.go:47`, `timeline.go:197`, `dsar.go:127`, `cases_http.go:126`); `/alerts`, `/search`, `/events`,
  `/logs`, `/incidents`, `/overdue`, `/subject`, `/searches/run` record nothing —
  and those are the console's primary reads. `docs/threat-model.md:184` bounds the malicious-operator
  insider with "who LOOKED is recorded"; a UI turns that adversary's task into "scroll the fleet and leave
  nothing". Per-route decision on what is an evidence-bearing read, recorded before the response, residual
  stated for every route left unaudited. Plus: migration `007_investigation_views.sql` has **no TTL, no
  purge and no DSAR path** while storing raw non-pseudonymised operator identities — a console makes it one
  of the largest tables in the database. Adds a retention window, purge, and DSAR inclusion.
- **CONSOLE-6 · Keyset pagination** — new work · M. `maxSearchLimit = 1000` (`operator_read.go:281`) with
  no cursor and no `has_more`. Hunt cannot be built on "top 1000 rows, no row 1001" against 90-day
  retention. The existing `ORDER BY received_at DESC, id DESC` is already a usable cursor.
  *Residual:* no stable snapshot across pages while ingest is live.
- **CONSOLE-7 · Operator-tier `/health`** — new work · S. Leader held / broker connected / ingest state /
  schema skew / last anchor. The Overview strip's first tile **has no data source today**: `/metrics` sits
  behind a separate constant-time bearer token (PLAT-4b), not the operator session. Also specifies what the
  console shows when it is talking to a follower.
- **CONSOLE-8 · Fleet inventory + break-glass surface** — CONSOLE-7 · M. Agent identity, platform, version,
  last-seen, attestation verdict + TTL, posture, spool depth — and **which agents are enforcement-suppressed,
  since when, by whom, until when**, from `agent_enforcement` (`heartbeat.go:72`).
  `INVARIANTS.md:131`: *"'How do I stop this?' is the question a CISO asks before 'what does it detect?'"*
- **CONSOLE-9 · Entity surface over HTTP** — new work · M. The entity graph (D203) and per-entity risk
  (D255) are database-only; no HTTP route exposes either.
- **CONSOLE-10 · Replay + explain over HTTP** — new work · M. `openshieldctl replay` is CLI-only. Backs the
  thesis page: which pack and rule won under the most-restrictive-wins lattice (ADR-5), and whether current
  policy still produces this decision.
- **CONSOLE-11 · Untrusted-render component + approval hardening** — CONSOLE-3 · M. One `<Untrusted>`
  component is the **only** path telemetry reaches the DOM, with an href scheme allowlist applied inside it
  — "a pivot menu on every value" turns every telemetry string into a potential `href`, and
  `javascript:`/`data:` are blocked by no CSP directive. Tree-wide lint ban on `dangerouslySetInnerHTML`.
  The four-eyes screen renders a **server-generated closed-vocabulary summary** (verb, subject count, blast
  radius, TTL) above the requester's free text, and the approve POST carries a one-time token bound to
  `(approval_id, requester, digest of the summary shown)` so a stale or re-rendered row fails closed.
- **CONSOLE-12 · Hunt, Fleet, Explain + the pivot spine** — CONSOLE-6,8,9,10,11 · L. The roadmap names
  five verbs — pivot, search, compare hosts, replay, explain a block — and the spine is what serves them:
  ⌘K palette, a global time range in the URL, a pivot menu on every value, every view URL-addressable so an
  IR handoff is a pasted link, and the whole loop completable by keyboard.
  **Two scope cuts, both sequencing rather than refusal.** *Split-pane compare* moves to `CONSOLE-39`: it is
  among the most expensive affordances to build — duplicated view state, two independent time ranges, a
  layout every later page must respect — and because every view is URL-addressable by design, two browser
  tabs serve "compare hosts" in the MVP. *The standalone Entity page* folds into the entity panel the
  incident detail already carries; `CONSOLE-9`'s HTTP surface still ships on schedule because Fleet, the
  incident detail and the risk score all need it. An entity is something an analyst pivots *to*, not a
  destination reached cold — so this removes a surface without removing a capability.
- **CONSOLE-13 · i18n foundation** — CONSOLE-4 · M · **moved to Phase 3 (see below), sequencing only.**
  `react-i18next` + ICU; **bundles embedded and signed with the release, never loaded from a mutable
  directory** — an unsigned hot-loaded pack rewrites UI text
  including the four-eyes button label, and `threat-model.md:193` requires signatures on everything loaded
  before parse. Approval confirmations and destructive-action labels live in a **non-overridable embedded
  namespace**. Gates: an ESLint rule failing CI on bare user-visible strings, and an `en-XA` pseudolocale
  render test. Logical CSS properties from day one so RTL is a data change later.
  *Residual, named:* backend-emitted reason strings stay English and render verbatim — the honest claim is
  "the console chrome is localizable; the security narrative is not yet" (see `I18N-2`).
- **CONSOLE-25 · Step-up re-authentication for destructive acts** — CONSOLE-3 · S. §2.3 of the design
  concedes the console *introduces* a privilege escalation: a stolen bearer token is effectively read-only
  today, a session is write-capable by definition, and a certificate is not phishable while a session is.
  Step-up is the compensating control every buyer expects and the plan had omitted — re-prove identity
  (`acr_values` / `max_age`, phishing-resistant factor) at `CONTAIN`, `ENFORCEMENT_DISABLE`, legal-hold
  release, DSAR export and case closure. **Binds to the one-time confirmation token `CONSOLE-11` already
  issues**, so it is nearly free there and expensive anywhere else. Also the first place the product states
  that MFA is delegated to the IdP — currently unstated anywhere, and it is a line item on every security
  questionnaire.
- **CONSOLE-26 · The queue as a worklist: assignment + bulk operations** — CONSOLE-4 · M. Without it the
  MVP is a viewer, not a console: SOAR-2's lifecycle is attributed but nothing says *whose* an incident is,
  so there is no "my queue", no unassigned bucket and no shift handover; and acknowledging a 200-incident
  phishing wave is 200 round trips. Bulk returns **per-item results** (partial success is the norm), writes
  **one audit row per item, not per batch**, and a bulk *containment* interacts with SOAR-7's blast-radius
  ceiling by being refused as a whole rather than partially applied.
  **State the distinction explicitly in the ticket:** SOAR-6 deliberately refuses per-analyst aggregation
  as workforce surveillance, with a test asserting no series names an operator. **Assignment is workflow,
  not measurement** — say so, or this gets refused for the wrong reason.
- **CONSOLE-27 · Suppression with mandatory expiry + closure disposition** — CONSOLE-4 · M. `No
  alert-storm suppression` is a named limit today. Weeks one to four of any deployment are dominated by
  tuning, and with no scoped expiring mute the analyst does the only thing available: disables the detector
  or ignores the queue. **This is the single most common reason a security-tool pilot is judged "too
  noisy".** Design it as a control, not a convenience: default TTL, mandatory reason, an owner, the
  suppressed count visible on the rule, audited creation, and **expiry that RESTORES detection** — the same
  shape as the intent TTLs the product already uses. Closure disposition (true positive / false positive /
  benign-authorized / duplicate) rides along: it is XS in the schema *while `CONSOLE-4` is being built* and
  a backfill across an attributed forward-only lifecycle afterwards, and without it there is no
  false-positive rate per rule to drive the tuning it enables.
- **CONSOLE-28 · Export from every grid** — CONSOLE-5,6 · S. CSV/JSON from any result set. Cheapest
  table-stakes item on the list, and it **strengthens** the boundary `CONSOLE-5` defends rather than
  weakening it: a bulk export *is* the "scroll the fleet and leave nothing" event, so it is view-audited
  with row count and filter, and it is the natural first signal for the per-viewer volume anomaly detection
  `CONSOLE-5` already proposes.
- **CONSOLE-29 · Session inventory, revoke-all, and deprovision kills live sessions** — CONSOLE-3 · S.
  `requireTier` re-resolving the role per request covers *authorization*, not session *existence*, and it
  does not cover "the analyst left and their laptop is unlocked in a shared room". Enumerate active
  sessions, terminate one or all, and make ZT-7 SCIM deprovisioning and an `operator-role` revocation
  invalidate live cookie sessions. The server-side session store is being built in `CONSOLE-3`, so this is
  a query and a delete **now**, and a security incident later.
- **CONSOLE-40 · Stable rule identity on alerts** — new work · S. **Blocks every tuning ticket below.**
  `unified_alerts` (migration 025) carries `domain` and `dedup_key` but **no stable rule identifier**, and
  `dedup_key`'s own comment calls its format "a projection detail" with a fallback. So "which rule is
  noisiest", "suppress *this rule* on *these hosts*" and "what is this detector's false-positive rate" are
  all unanswerable without parsing a key that is explicitly not a contract. Adds `rule_id` written by every
  producer, with a whole-tree guard — the same shape as the `cmd/` guard that made every binary declare its
  config (D274) — so a new detector cannot ship without one.
- **CONSOLE-41 · Tuning: disposition → exception, with a preview that cannot lie** — CONSOLE-27,40 · L.
  **This is the surface that decides whether the console gets used**, not an admin convenience: if week
  three produces forty alerts a day and thirty are noise, analysts stop reading the queue regardless of
  detection quality. Three distinct layers, deliberately not conflated — **disposition** (a fact about the
  past, no risk), **exception** (stops future matches; a deliberate coverage reduction, so audited,
  attributed, expiring, reviewable), **threshold** (fleet-wide sensitivity, a config revision). The operator
  is always offered the *narrowest* layer that would work. Exclusion lists are already sanctioned as "a
  first-class policy primitive" in `openspec/config.yaml`, so this surfaces a primitive the design has, not
  a new concept. `Accept`: an exception is **dry-run against the retention window before it exists**, and
  the dialog states how many alerts it would have suppressed **including how many were dispositioned TRUE
  POSITIVE** — tuning blind is how real detections get muted. Never-expiring requires admin plus a separate
  confirmation; default TTL 30 days; **expiry RESTORES detection**, like the intent TTLs.
- **CONSOLE-42 · Detector health + exception register** — CONSOLE-41 · M. Per rule: fired, FP%,
  dispositioned population, active exceptions, and a trend sparkline **annotated with tuning events** so
  "did that exception help" is visible rather than inferred. **FP% renders with the population it excludes**
  and is de-emphasised below a sample threshold — the same honesty SOAR-6 applies to MTTA/MTTR. Sorted by
  noise contribution (`fired × FP%`), not raw count. The register shows every exception's
  **suppressed-count since creation**: zero after 30 days means it does nothing and should go; thousands
  means the detection needs fixing rather than muting. Neither is visible anywhere today.
- **CONSOLE-43 · Learning mode** — CONSOLE-41 · M. A per-domain observation window where detections raise
  but do not enforce or page, with the end date on a banner and one-click promotion. Prevents the week-one
  alert storm that kills pilots.
- **CONSOLE-44 · Zero Trust access: catalog + effective-access matrix** — CONSOLE-9 · L. **Closes ZT-5's
  UI half, which this roadmap already said "ties to the UI (PLAT-1)".** Today the catalog is
  `OPENSHIELD_ACCESS_CATALOG` (an explicit allow-list, `internal/gateway/catalog.go:16`) and the policy is
  a **Rego module** (`cmd/openshield-gateway/main.go:349`) — both files, no UI, and *"who can reach the
  production database?"* is answerable only by reading Rego. Delivers the services tab (keeping HTTP
  reverse-proxy and TCP CONNECT distinct, because the code deliberately refuses to interchange them) and
  the **effective-access matrix**, readable in both directions, where **every cell is explainable** through
  the same decision trace as `CONSOLE-10`. Surfaces catalog↔policy drift: a service nobody can reach, a
  policy naming a service not in the catalog. Both are common and both are silent today.
- **CONSOLE-45 · Zero Trust policy authoring + sessions** — CONSOLE-44 · L. Rego stays the source of truth
  and **the console never becomes a second authoring model that drifts from it** — that is the failure this
  project keeps finding. The editor is the real module, with a dry-run evaluator (principal + posture +
  service → decision and rule path) and **diff + four-eyes on save**, because this is a change to who
  reaches production. A guided builder emits into the same module and shows what it wrote. Sessions: active
  principal/device/service, and **terminate one or all** — what an IR lead needs at 2am and cannot do from
  anywhere today. *Session recording is owner-gated and named separately: it carries a DPIA weight this
  product should not assume.*
- **CONSOLE-46 · The rule-source component family** — CONSOLE-12 · M. Every detection domain needs the same
  thing: a list of rules/feeds/baselines/lists where each entry shows origin (file / URL / operator),
  signature state where the artifact is signed, last reload, hot-reload vs restart-required, a dry-run, and
  diff-and-approve on change. **One component family reused five times, not five bespoke pages** — specified
  once here so `-47`…`-50` are assembly rather than design.
- **CONSOLE-14 · Assurance gates** — CONSOLE-12 · M. Clicks-to-answer budgets asserted in Playwright and
  CI-gating; axe/WCAG 2.2 AA; keyboard-only investigation path; **golden-response fixtures, not generated
  types** — most handlers return anonymous `map[string]any` (`incidents.go:195`, `soar2.go`,
  `config_http.go`), so a Go→TS generator degrades into "generate a few, hand-write the rest", the
  half-maintained source of truth this project keeps being burned by.
- **CONSOLE-15 · Console in the signed release** — CONSOLE-2 · M. JS SBOM generated **from the lockfile**
  and fed into `BuildSBOM` so the manifest signature covers it — `internal/release/sbom.go:55` derives from
  `debug/buildinfo` and would describe zero npm packages. Node/pnpm pinned in the manifest beside the Go
  toolchain. Security-header audit on the served console.

### Phase 3 · Deferred console surfaces — on the roadmap, not gating the MVP console

**Sequencing note on i18n, for the owner to overrule if they disagree.** Multilingual support is an owner
requirement and is NOT in question — the framework choice, ICU, the signed-bundle decision and the refusal
of the unsigned overlay all stand as written in `CONSOLE-13`. What moved is *when*. The plan's own residual
concedes the security narrative stays English until `I18N-2`, so what a Phase-2 `CONSOLE-13` would ship is
translated chrome above English alert reasons — a property no analyst can use and no procurement checklist
credits, bought with an M-sized ticket and two CI gates. **The two things that genuinely cannot be
retrofitted stay in Phase 0**, folded into `CONSOLE-2`: logical CSS properties from the first component
(`margin-inline-start`, never `margin-left`), and the no-bare-string lint rule. Those keep the retrofit
cheap; the rest waits for `I18N-2` to make it mean something.

- **CONSOLE-39 · Split-pane compare** — CONSOLE-12 · M. Two hosts or two incidents side by side, with
  independent time ranges. Deferred from the MVP spine, not refused — "compare hosts" is one of the five
  named adoption verbs, and two URL-addressable tabs are the interim answer, not the final one.

- **CONSOLE-16 · Standalone Overview dashboard** — CONSOLE-7 · M. (MVP ships a health strip on Incidents.)
- **CONSOLE-17 · Alerts as a first-class page** — CONSOLE-6 · M. Dedup by `dedup_key`, ATT&CK mapping, ack.
- **CONSOLE-18 · Response surface** — new work · L. Playbook definitions and runs, integration runners,
  notification routing. Needs `CONSOLE-19`.
- **CONSOLE-19 · Playbook read/validate/dry-run over HTTP** — new work · M. Playbooks are a polled file
  (`OPENSHIELD_PLAYBOOKS`) with no API. Read and dry-run first; authoring is a separate decision.
- **CONSOLE-20 · Evidence & ledger browser** — new work · M. Chain verification, anchors, witness,
  restore-drill history, and the view-audit reader.
- **CONSOLE-21 · Configuration UI** — new work · M. Schema-driven forms over `GET /config/schema`;
  bootstrap fields read-only with origin, dynamic editable; diff before save, revisions and rollback;
  secrets never readable back; **all field errors rendered at once** because the API already reports them
  at once. This is what PLAT-5's derived schema was built for (D262/D263).
- **CONSOLE-22 · Administration & integrations** — new work · L. Role management, enroll-token
  issue/revoke, feed ingest and status, fleet-control publish — **all CLI-only today**, each needing an
  HTTP route with four-eyes where the CLI relied on shell access as the gate.
- **CONSOLE-23 · Policy & compliance packs** — new work · M. Packs in force, lattice preview, simulation.
- **API-9 · Streaming (SSE), if a measured need appears** — 🔵 deferred by decision, not backlog. Cut from
  the MVP: correlation runs on a CLOCK (SOAR-2/D250) so streaming buys latency the backend does not
  produce, and a long-lived stream authorizes once at handshake — reintroducing exactly the role staleness
  ZT-7 deleted (`operator_roles.go:26`: *"the revocation takes effect within the cache TTL is the sentence
  that makes a security control untrustworthy"*). MVP polls with ETag/`If-None-Match` at 10–15s.
  *Residual:* freshness is bounded by the poll interval AND the correlation interval, and the second
  dominates. If this lands, the stream loop must re-resolve the role on a tick, tear down on mismatch, and
  cap its lifetime below the session idle timeout.
- **CONSOLE-24 · Session sender-constraining** — CONSOLE-3 · M. Non-extractable WebCrypto keypair or DBSC,
  so `REQUIRE_DPOP=1` no longer has to refuse console login. Until then the refusal is the honest answer.
- **I18N-2 · Localizable security narrative** — CONSOLE-13 · L. Message IDs + params at the emission point
  instead of pre-formatted English strings, so alert reasons and policy explanations localize. This is the
  half that makes "multilingual" true rather than "the chrome is translated".
- **CONSOLE-30 · Custom roles / per-capability grants** — CONSOLE-1 · M. Beyond the four tiers
  `CONSOLE-1` leaves in place. A capability table behind the existing `requireTier` seam, so the grant is
  data rather than a new gate. Procurement asks for this by name in an access review.
- **CONSOLE-31 · Reporting: scheduled reports, exec PDF, compliance evidence packs** — CONSOLE-20 · L.
  Today `SIEM-9` parks scheduled reports in enrichment and no console phase has a report page, while the
  CISO's actual recurring deliverable is a board slide and the auditor's is an evidence pack mapped to
  SOC 2 CC7 / ISO 27001 A.12 / PCI 10 / HIPAA §164.312(b). **This is where the product's strongest claim
  becomes an artifact:** a report rendered server-side, deterministically, with a hash-chain-verifiable
  evidence appendix is something the incumbents cannot produce. Skipping it forfeits the differentiator in
  the one document executives actually read.
- **CONSOLE-32 · Audit egress — forward the console's own audit log to the customer's SIEM** — new work ·
  S. OpenShield ingests CEF, syslog, CloudTrail and WEF and **emits nothing**. Enterprises require operator
  actions, authentication events, config changes and admin activity to land in *their* SIEM, not only in
  the vendor's database. One CEF/syslog emitter over the existing audit rows. A SIEM-ingesting product with
  no audit egress is a contradiction an evaluator finds in the first technical call.
- **CONSOLE-33 · Onboarding, empty states, deployment self-diagnosis** — CONSOLE-7 · M. A fresh install
  shows an empty queue, which is **indistinguishable from a broken install**. `CONSOLE-7` delivers health
  *facts*; this delivers a *diagnosis*: "0 agents enrolled — here is the enroll command", "ingest connected
  but no events in 24h", "3 agents silent for 7 days", "your schema is one migration behind". For an
  open-source product where adoption is the distribution channel, this is plausibly the highest-ROI item in
  Phase 3 — the evaluator decides in twenty minutes.
- **CONSOLE-34 · OpenAPI document validated against the golden fixtures** — CONSOLE-14 · S. §10 rejects
  *generated types* for good reason, but that leaves no published contract at all, and "send us your API
  docs" is question two on every RFP. A hand-written OpenAPI doc checked in CI against the fixtures
  `CONSOLE-14` already records costs one job and promotes those fixtures from a private test artifact to a
  conformance corpus.
- **CONSOLE-35 · Shared team views + watchlists** — CONSOLE-12 · M. SIEM-14 shipped saved searches, but
  they are personal: no manager-curated team triage view (an owner/visibility column on the existing
  table), and no watchlist for VIPs, crown-jewel hosts or contractors under review. The watchlist should
  feed the entity risk score (D255) rather than being a UI filter — otherwise it is decoration.
- **CONSOLE-36 · SLA timers + breach alerting on the live queue** — CONSOLE-26 · S. SOAR-6's own residual
  names this gap: the console renders historical MTTA/MTTR while showing an analyst nothing about the
  incident in front of them aging past a commitment. Per-severity target, a computed clock on the queue
  row, and breach routed through SOAR-9's existing sinks. TABLE-STAKES for an MSSP, who sells contractual
  response times.
- **CONSOLE-37 · Multi-tenancy** — CONSOLE-1 · XL · 🔒 owner decision. ADR-4 defers org tenancy and
  `docs/enterprise-gap-assessment.md` §3 names zero tenant scoping as an evaluation-ending gap. `CONSOLE-1`
  reserves the seam so this is a WHERE clause; whether to build it is a positioning call (MSSP resale and
  subsidiary/region isolation) rather than an engineering one.
- **CONSOLE-38 · VPAT, browser support matrix, theming seam** — CONSOLE-14 · S. `CONSOLE-14` already funds
  the real accessibility work (WCAG 2.2 AA, axe in CI, keyboard-only path); the **VPAT is the artifact US
  federal and large-enterprise procurement actually requests**, and it is a document, not a project. State
  the browser floor too — `CONSOLE-24`'s WebCrypto/DBSC path implies an aggressive one. Theming via CSS
  custom properties is near-free during `CONSOLE-2` and expensive after fourteen components ship; white-label
  itself stays a DIFFERENTIATOR for MSSP resale.
**The administration gap, named as one thing.** A coverage matrix over every product domain (UX spec §13)
found one pattern: **every domain that detects has a shipped, tested detection plane and no way to see or
change what it is detecting on without editing a file on a host.** The five tickets below close it. None
gate the MVP console; together they gate the sentence *"an administrator can run this product from the
console"*, which is a different and later claim. Each is assembly over `CONSOLE-46`.

- **CONSOLE-47 · Endpoint control** — CONSOLE-46 · M. Exec allow/deny lists and default-deny whitelisting
  (D217/D224/D230), FIM baselines (D223/228/229/236), ransomware canary placement (D232), USB enforcement.
  All shipped and VM-proven; none has an operator surface.
- **CONSOLE-48 · Network defense** — CONSOLE-46 · M. IOC threat-intel feeds, content signatures, DNS
  sinkhole lists, CASB catalog, TPROXY scope. Signature state matters here — D297 fixed the gateway reading
  its IOC feed unverified, so the surface must render verified-before-parse rather than imply it.
- **CONSOLE-49 · DLP classifiers & indexes** — CONSOLE-46 · L. EDM/IDM index lifecycle with **signed
  indexes (ADR-9)**, detector breadth per national ID type, compliance packs in force and the
  most-restrictive-wins lattice preview, exfil-channel coverage. Merges with `CONSOLE-23`.
- **CONSOLE-50 · Device trust operations** — CONSOLE-8 · M. Enrollment tokens and self-enrollment status,
  attestation verdict history, **measured-boot PCR policy** (a typo in a PCR list silently narrowed
  attestation once, D413 — a surface that shows the effective PCR set is the guard), attestation TTL,
  re-attestation failures.
- **CONSOLE-51 · Privacy operations** — CONSOLE-1 · M. DSAR request → compile → deliver as a workflow
  rather than a `/subject?id=` link; legal holds with what they block and who released them; retention and
  purge status; erasure verification. Gated on the `privacy-officer` tier from `CONSOLE-1`.
- **UI-19 · Signed locale packs** — CONSOLE-13 · M. Verified against the operator key before parse, same
  loader as rule bundles and IOC feeds; `{lng}`/`{ns}` pattern-matched and resolved under the root; the
  non-overridable namespace still wins. The **unsigned** overlay is REFUSED, not deferred.

---

## 🗺️ Lane G · Topology — declared, compiled, and applied only over a signed channel

Its own lane, sequenced after the console MVP because it serves none of the five adoption verbs. There is
no topology, site or zone concept anywhere today (`grep -riE "topology|site_?id|zone_?id"` over `.go`
returns nothing). ADR-15.

- **TOPO-1 · Topology model + drift** — CONSOLE-8 · L. Typed nodes (control-plane server · worker · gateway
  in one of four modes: egress proxy, ZT access proxy, inline TPROXY, DNS sinkhole · endpoint agent group ·
  internal service · external network · identity provider · broker · database · integration sink ·
  site/zone). Every node is **discovered** (bound to a real enrolled agent or gateway by canonical device
  identity, IDENT-1/ADR-6) or **declared**. Edges are typed and typechecked: `routes-traffic-to`,
  `protected-by`, `enrolls-with`, `publishes-to`, `authenticates-against`. Revisioned like PLAT-5 config —
  author, diff, rollback, audited. **Drift ships here and needs no canvas**: declared-but-not-enrolled,
  enrolled-but-not-declared, and gateways enforcing rules the topology does not declare, as a list on the
  Fleet page. Without drift this is a drawing tool.
- **TOPO-2 · The canvas** — TOPO-1 · L. `@xyflow/react` node editor: draw, bind to discovered fleet,
  drift overlay, autolayout, validation. This is the only ticket that justifies the canvas dependency, and
  it is charged to this ticket rather than to the console's budget.
- **TOPO-3 · Routing compiler (dry-run only)** — TOPO-1 · L. A **pure function**: graph → *proposed*
  gateway configuration plus CASB/policy/feed catalogs, with a validated per-node diff. Generates, never
  applies. Pure means directly testable: given a graph, assert the emitted config.
- **TOPO-4 · Signed gateway-configuration channel** — 🔒 **owner-gated** · XL. Gateway config is
  deliberately all bootstrap-scope, node-local, with no database credentials (D272), so apply cannot go
  through the config DB. Three constraints are the whole design: **(1)** it must not become a second
  command channel — `INVARIANTS.md:27` bounds a compromised control plane because *"there is no message
  meaning 'run this'"*, and configuration is where enforcement lives, so **a compiled config that reduces
  enforcement coverage must be REFUSED unless expressed as `ENFORCEMENT_DISABLE`**, computed by the
  compiler as a coverage invariant, so it inherits `fleetcontrol.go:22`'s mandatory four-eyes, monotonic
  sequence and TTL instead of routing around them — otherwise "draw the gateway out of the path" disables
  the fleet silently and "empty the feed catalog" stops it blocking known-bad while it reports healthy;
  **(2)** approval is **semantic** — nobody approves a compiled routing diff by inspection, so the screen
  says *"prod-web loses inline inspection"*, never a field diff; **(3)** rollback must not flap — self-check
  is **locally observable only** (config parses, rules load, counters increment) and never depends on a
  network path an adversary shares, rollback targets a **named signed known-good revision** rather than
  "previous", rate-limited per node, **fail-static** (keep last-good enforcing, raise an alert) rather than
  fail-flap, every rollback audited.
- **TOPO-5 · Apply from the canvas** — TOPO-4 · L. Four-eyes plus staged rollout over the channel.

---

## 🟢 Enrichment backlog — post-MVP, none of it gating

**Everything below this line is enrichment**: additive producers, classify plugins and typed context that
land on the frozen core without gating the MVP. The intro promises this section by name; until now it had
no header and its items sat as subsections of the MVP queue, which read as though they were required.
They are not. Pull from here opportunistically, or after the UI (PLAT-1).

Several entries below are marked ✅ **DONE** — KERNEL-1, the broker-lifecycle work, DSPM-1, ZT-7. They
are kept in place rather than moved to the Done ledger because each records the **residuals** its ticket
did not close and the reasoning that found it, which is the part worth re-reading before proposing
adjacent work.

### DLP
- **DLP-2 · Remaining exfil surface** — P, per-OS · L. Screenshot capture (display/OS-gated) + CASB
  refinements (multipart/path upload heuristics, download/share, shadow-IT discovery, runtime mount-table
  resolution). *(Clipboard + print producers are MVP — Lane E; file + cloud-sync + CASB already ship.)*
- **DLP-3 · OCR** — classify (server-side, ADR-9) · L. EDM/IDM/signed-index already ship; OCR is the last
  DLP-3 piece — server-side for gateway-visible flows, never breaking D10/D11.
- **DLP-6 · Endpoint user coaching/justification** — X + UI · M. REDIRECT-to-coaching exists at the
  network gateway; bring it to the endpoint. (Depends on the UI.)
- **DLP-7 · More national IDs / richer context rules** — classify · M. Copy the checksum/context shapes;
  extend via the signed custom-rule surface.
- **DLP-8 · Format depth** — classify · M. Nested-archive recursion ships; remaining: RTF, legacy `.doc`,
  tar/gzip containers, response-body multipart/gzip (shared with NIPS-4).

### NIPS / NTPS
- **NIPS-1 deferred increments** — D. nftables-native backend, TPROXY bypass watchdog, OUTPUT/local-host
  case, IPv6, streaming inspection past the peek window, TLS interception, structured HTTP parsing.
- **NIPS-2 · Full signature engine** — C. Suricata/Snort grammar (flowbits/offset-depth/thresholding),
  Aho-Corasick multi-pattern, response-body scanning, STIX/TAXII + authed feeds, JA3, **SMTP content
  filtering** (the SMTP parser ships in the Done ledger; acting on its content is here). (IOC + content-
  signature halves already ship.)
- **NIPS-5 · HTTP/2 & QUIC interception** — new work · L. HTTP/1.1 only today.
- **NIPS-6 · Raw TCP/L4 metadata connector + anomaly/beaconing detection** — P + C · L. **BEACONING
  SHIPPED (D280)**: MAD-based regularity over verified flow metadata, grouped per subject, medium-severity
  and evidence-carrying with an allowlist as configuration — because legitimate software beacons
  constantly and a detector that is mostly known-good gets muted. **Scheduled on its own leader-only loop (D281)** — a 24h rhythm window cannot ride a 1h correlation tick,
  and zero means idle so it turns on without a restart. *Remaining:* the raw L4 connector, other anomaly
  families, and process attribution.
- **NIPS-8 deferred increments** — D. Local cache + upstream failover, sinkhole-to-walled-garden IP, TCP
  DNS, DoT/DoH, nftables-native backend. (Resolver + transparent redirect (local + forwarded) + bypass
  watchdog already ship.)

### SIEM
- **SIEM-9 · Threat-intel enrichment + saved searches / scheduled reports + more ingest formats** — S–M /
  M. **RFC 5424 syslog SHIPPED (D279)** — one listener accepts it alongside CEF, and its structured data
  is huntable as `fields` exactly like a CEF extension. *Remaining:* JSON-lines, GELF, saved searches,
  scheduled reports; no cross-vendor field normalization and no unified severity scale (both are decisions
  about whose vocabulary wins, not missing code).
- **SIEM-10 remainder** — record the gateway ledger-tombstone purge as a compliance event; scheduled
  report export. (Retention-event recording + `GET /compliance/retention` already ship.)
- **Field-hunting deepening** — typed columns for the `fleet_telemetry` proto `BYTEA` payloads; free-text
  search over `raw`; cross-vendor field-name normalization. (JSONB field hunting across CEF/CloudTrail/WEF
  already ships.)

### HIPS
- **Real-time behavioral hooks** — eBPF/LSM `mmap`/`mprotect`/exec hooks replacing the poll for
  memory-injection + FIM; a JIT allowlist for legitimate W+X (JVM/V8/.NET); per-process ransomware
  attribution; content-hash application whitelisting.
  *(Full-pipeline inline `DENY_EXEC` is MVP — Lane E, HIPS-3 inc 2.)*

### Privileged tests — found by asking why coverage stalled at 52.7% (D381)
- **KERNEL-1 · The dnsredirect kernel tests were FLAKY under real root, and ran nowhere** — ✅ **DONE (D382).**
  Root-gated tests skip on every developer machine and in CI, so this suite executed only when somebody
  remembered the VM. Run there, it passed test-by-test, passed the FIRST package run, and failed the next —
  a different test each time, always `connection refused` against the canned upstream.
  **The cause was CONNTRACK.** A nat REDIRECT decision is cached PER FLOW, and removing the rule does not
  flush the entries it created — a UDP entry outlives the test by ~30s. A later query whose source port
  collided with an earlier one was still DNAT'd to a resolver port that had since closed. So the damage was
  done by the PREVIOUS run, which is why nothing in the current one explained it. Clearing both rule chains
  (the transparent OUTPUT one and the forwarded PREROUTING one) was necessary and did not fix it, because
  the leftover was never a rule.
  Fixed by giving each test its OWN loopback upstream address — a different conntrack tuple, so no stale
  entry can match — rather than flushing, which needs the `conntrack` tool a contributor may not have.
  Four consecutive clean package runs under real root, where it previously failed two in three, and it is
  now in the CI kernel job.
  **The same shape was then found in the gateway (D389)** and closed: `internal/gateway` ships four
  `*_kernel_test.go` files covering TPROXY redirect, SNI blocking, rule lifecycle and re-arm, and the
  kernel job ran none of them — *"`internal/gateway` has kernel tests"* and *"CI runs `internal/gateway`'s
  kernel tests"* look identical from the outside, which is why it survived as long as it did. Unlike the
  DNS redirect, these were not broken when finally run: all five passed first time on a real kernel.
  The job now builds and runs the open gate, `internal/dnsredirect` and `internal/gateway` under real root.
  *Still outside that job:* `internal/dnssink`'s VM tests, and `internal/clipboard/x11` — which needs only
  `xvfb-run`, not root, so it is gated on a display rather than on privilege (and whose tests leaked
  children that pinned two cores for an hour until D393).

### Broker lifecycle — found by the offline-queue recovery test (D367)
- **Endpoint partition + ping detection: ✅ DONE (D369).** A container-based scenario removes the AGENT's
  interface and rejoins it on a different IP. It found a second defect D368 could not help with: an endpoint
  whose interface vanishes holds a TCP connection that is dead and looks open, and nats.go's keepalive
  defaults (`PingInterval=2m` x 2) meant **four minutes** before anything noticed — `IsConnected()` stayed
  true, so no reconnect was attempted and every spool drain timed out while the spool grew 4 -> 76 records.
  You cannot reconnect a connection you do not know is broken. Now 20s x 2 (~40s), and the scenario went
  from failing at 208s to passing at 66s. **All four of the enterprise assessment's unproven properties are now closed** — partition (D369),
  offline-queue drain (D367/D370), clock skew (D377, narrowly — see below), and per-node limits under
  contention (D378). D378's finding: the file-open gate's three discard counters — dropped AUDIT ROWS
  (decisions not in the ledger, against D358), unclassified gated opens, and suppressor-declined opens —
  were logged only at `ctx.Done()`. Every one fires under contention, which is exactly when nobody stops the
  process to look, and a SIGKILLed or crashed engine never reported at all. Now on the existing
  `reportDiscards` mechanism the listeners got in D348. *Residual:* it makes the loss visible, not
  preventable; dropped audit rows are not recoverable (the counter says how many, not which); and the engine
  still has no metrics endpoint by deliberate choice, so a scraper reads the log.
  Clock skew is DONE (D377) with a narrower result than expected: liveness was already immune (SEC-3 reads
  the control plane's own receipt time), and beaconing necessarily trusts the endpoint's clock. Only the
  FUTURE direction is decidable — an event cannot be observed after it was received — and bounding the past
  as well destroys detection outright, because every event spooled while an agent was offline (D40/D67) is
  legitimately past-dated (measured: 1 detection to 0). So backward skew, and therefore the beaconing
  evasion in its most likely form, is NOT closed and needs a time source the endpoint does not control. Also untested: a whole SEGMENT partitioning and reconnecting together, which
  is what the D368 jitter is for.
- **Reconnect forever: ✅ DONE (D368).** Every long-lived process ran on nats.go's defaults
  (`MaxReconnects=60` x `ReconnectWait=2s` ~= two minutes, then a permanent close with the process still
  running). Measured: a 4s outage recovered fully, a 150s one never did. The agent case is the one that
  matters — it kept producing into the spool that exists to prevent silent loss and could never drain it,
  so the spool filled to its ceiling and began dropping the OLDEST records. `natsx.ResilienceOptions` now
  gives infinite reconnect + jitter + disconnect/reconnect logging to the agent, engine, gateway and
  `controlplane.Run` (NOT `Connect`, which is for one-shot operator subcommands). *Residual:* "the agent is
  running" no longer implies "connected" — the log line and the dead-man's-switch are what cover that.
- **PLAT-10 · A broker that returns with empty JetStream state wedges the fleet, silently** — ✅ **DONE (D370)**. `Server.healIngest` polls the durable consumer every 15s and, on finding it or its stream gone, announces that ingest is DOWN, recreates the stream and resubscribes; repairs and repair failures counted separately. A POLL rather than a reconnect handler, because a stream can be deleted while the connection stays healthy and no handler would fire. Repair is narrow (only a missing consumer/stream) so a transient error never churns a working subscription. *Residual:* records published into the gap were REFUSED by the broker, not buffered — they return only as producers drain their spools; and a repair recreates the stream with its ORIGINAL config, overwriting any deliberate operator tuning. Original finding below.
  **Reproduced, not theorised** (`Stack.RestoreBrokerEmpty` exists for it): stop the broker, bring one back
  on the same port with a fresh JetStream store, and telemetry never resumes. Measured: rows frozen for
  30s+ while the agent publishes every 500ms, and **the control plane logs nothing at all**. A
  volume-backed restart of the same broker recovers fine (2 -> 120 rows), which is what makes this
  specific and not a general "outage" story.
  Cause: `natsx.EnsureTelemetryStream` is called from exactly two places —
  `controlplane.Run` and `SignedPublisher.UseJetStream` — both at **process startup only**. A broker with
  no stream therefore stays without one. The agent's publishes fail forever (`no response from stream`,
  at least logged agent-side); the server's durable push consumer was deleted with the stream and it says
  nothing. Every agent's spool then grows to its 10,000 ceiling and begins dropping the OLDEST records.
  This is not exotic ops: `podman rm` + recreate the broker, or an orchestrator rescheduling it onto new
  storage, produces it exactly.
  **It needs BOTH halves and a half-fix is worse than none:** re-ensuring the stream from the agent on
  reconnect recreates the stream while the control plane's consumer stays dead — so the stream exists,
  publishes succeed, and still no row appears, which is harder to diagnose than the current failure. The
  fix is a reconnect handler on the control plane that re-ensures the stream and RE-SUBSCRIBES (tear down
  `sigSub`, resubscribe with the same durable), plus the agent-side re-ensure. **Minimum bar even if
  self-healing is deferred: the server must say something** — a silent fleet-wide telemetry outage is a
  direct D31 violation, and D31 is the reason the rest of this product is trustworthy.

### Data-at-rest discovery (DSPM) — from the enterprise gap assessment
- **DSPM-1 · One object-store discovery connector** — ✅ **DONE (D371)**. `internal/connectors/objectstore`
  sweeps an S3-compatible bucket on an interval, reads a bounded prefix of each object via a ranged GET, and
  feeds the same pipeline everything else feeds; content goes to the sandboxed worker via the content store
  and never onto the Event. No SDK — SigV4 hand-rolled over stdlib HMAC, so the twelve-direct-dependency tree
  is unchanged AND the connector works against MinIO/Ceph/R2/Wasabi rather than only AWS. Proven against a
  real MinIO, because a mocked S3 would agree with whatever the signer believes.
  **THE FITNESS VERDICT (recorded in `sweep.go`, and it reversed the plan):** the producer seam
  (`Next(ctx) (*corev1.Event, error)`) fits a pull/enumerate producer unchanged — that half held cleanly. The
  proposal then said to avoid a contract change by carrying `s3://bucket/key` in
  `FilesystemSubject.resolved_path`, and TRYING IT SHOWED THAT BACKWARDS: `Event.target` is a oneof that
  exists so a producer can carry its own shape, and ClipboardSubject/PrintSubject are the precedent. So
  `ObjectSubject` is idiomatic and the URI-in-a-path was the invasive option. Answer to "does the pipeline
  absorb a new capability by adding a plugin?": **yes**, and this is the strongest evidence yet because the
  producer shape was genuinely new rather than isomorphic — with the caveat that it survived because the
  contract had a designed-in growth point, not because the contract never changes.
  *Residual, and each is stated in the capability spec rather than implied:* no ACCESS CONTEXT (who can reach
  the bucket) — that is the other half of what DSPM buyers mean; one store family only; a PREFIX per object,
  so content past the ceiling is unexamined; no incremental since-last-sweep state, so every sweep
  re-enumerates; read-only, no remediation.
  **MinIO is in `compose.yaml` for DEV ONLY** — OpenShield scans an object store, it does not provide one,
  and production points at whatever the operator already runs. **The largest name-versus-capability
  gap in the product** ([`enterprise-gap-assessment.md`](enterprise-gap-assessment.md)): OpenShield
  classifies data IN MOTION past an interposition point, and the only cloud surface that exists is
  CloudTrail *log ingest* (`internal/connectors/cloudtrail`) plus AWS-key secret detection in
  `internal/classify/secrets.go`. There is no S3, Azure Blob, GCS, M365/SharePoint or Google Workspace
  enumeration, so the product cannot answer **"where is my sensitive data"** — the first question asked of
  anything called a Data Security Platform. Data in a bucket is invisible until someone touches it on an
  instrumented host.
  Scope one store (S3 is the obvious first): enumerate objects, fetch a bounded prefix, feed the EXISTING
  classifier, emit findings as Events with a store/bucket/key subject. **Not architecturally hard** — the
  classifier, the boundary and the audit path all exist; it is absent because it was never queued.
  **And it is the strongest available test of the D26/D69 fitness claim**, better than the S3 connector
  T-014 dismissed as isomorphic: a discovery producer **pulls and enumerates on a schedule** rather than
  being pushed events, which is a genuinely new producer *shape*. If that forces a core change, the
  10-year claim needs revisiting — finding that out is the point.
  *Honest scope note:* discovery without **access context** (who can reach this bucket) is half of what
  DSPM buyers mean; the other half is a separate ticket and should not be implied by this one.

### Zero Trust
- **ZT-5 · Policy admin + session recording** — **now scheduled as `CONSOLE-44` + `CONSOLE-45` in Lane F.**
  This entry said "ties to the UI (PLAT-1)" and the first console plan missed it: the access catalog is an
  allow-list string and the access policy is a Rego module, both files, so *"who can reach the production
  database?"* is answerable today only by reading Rego. `CONSOLE-44` delivers the catalog and the
  effective-access matrix, `CONSOLE-45` the authoring and session termination. **Session RECORDING stays
  owner-gated and out of both** — it carries a DPIA weight this product should not assume, and it is a
  separate decision from policy administration.
- **ZT-7 · Operator identity: SSO, and the role out of the certificate** — ✅ **DONE (D372, D373, D375, D379,
  D380).** Rewritten as one entry: successive in-place edits had spliced the history mid-sentence and it had
  stopped being readable.

  **The defect (D372).** The RBAC tier was stamped into the operator's client certificate and read from
  there, so authorization was frozen for the certificate's lifetime — a demotion or removal did not take
  effect until it expired, and there was no "revoke this operator now" primitive at all. The role now lives
  in `operator_roles`, resolved server-side per request. Revocation is a ROW, not a delete (a delete falls
  back to the certificate and restores it); a database error DENIES rather than falling back (fail-open is
  right for enforcement per D17/D18 and wrong for authorization); `agent` is not grantable, so one
  compromised endpoint is not a compromised console; no cache, because a TTL sells back the immediacy.

  **SSO (D373).** Operators may present an OIDC bearer token. **The token's claims do NOT decide the role** —
  a group-to-tier mapping reintroduces the defect with a shorter fuse. Consequence: an SSO operator has no
  certificate and therefore no fallback, so they are strict by construction while certificate holders
  migrate.

  **It shipped unusable, and an INTEGRATION test found it (D375).** The HTTP surface required a client
  certificate at the handshake, so an SSO operator was refused before the token was read; the feature could
  not run in any deployment. Package tests could not see it — they drive a handler with a synthesised TLS
  state. Fixed with `VerifyClientCertIfGiven` scoped to SSO-enabled deployments. The assertion guarding that
  relaxation was itself VACUOUS at first (a client from a second PKI fails the handshake client-side, so it
  passed against a mutant with no server-side verification at all) — when asserting one side rejects
  something, the other side must have no reason to fail.

  **Sender-constraining (D379).** A token carrying `cnf.jkt` needs a DPoP proof bound to method and URI,
  single-use and fresh; a bound token reaching a verifier that cannot check proofs is REFUSED, not
  downgraded; `OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP` refuses UNBOUND tokens (off by default — on before the
  issuer binds locks everyone out).

  **SCIM (D380).** Deactivation revokes IMMEDIATELY on the credential already held, as a row, accepting all
  four provider dialects, behind its OWN constant-time token — an operator credential reaching it would let
  an analyst deactivate an admin. **Provisioning grants NOTHING**, so this closes the LEAVER half of
  joiner/mover/leaver and the joiner half still ends with `operator-role set`.

  **Residual, and each is stated rather than implied:** no JIT provisioning; the SCIM subset is
  userName/active with one filter shape and no groups, bulk, `/Me` or schema discovery, so a provider
  requiring `ServiceProviderConfig` may refuse to connect, and none of it is tested against a real IdP;
  `htu` comes from the Host header, so a proxy rewriting it breaks proofs; DPoP replay rejection is bounded
  by a cache; no four-eyes on a grant (SOAR has it, this does not); and certificate revocation proper is
  unchanged — revoking authorization leaves the identity able to authenticate, just unable to do anything.
- **ZT-6 · SAML** — P · L. Only after OIDC proves the SSO seam. Note ZT-7 is the *operator* half; ZT-6 and
  the existing OIDC are the *subject* half, and conflating them is how the SSO gap stayed invisible.

### Cross-platform (Windows/macOS)
- **PLAT-7 · Native OS watch + Windows/macOS validation** (ADR-11) — L. The OBSERVE path already runs
  off Linux via the poll-based `openFileWatcher` seam; enrichment finishes it: native OS watch APIs
  (`ReadDirectoryChangesW`/`FSEvents`), a non-Linux worker sandbox (seccomp is Linux-only), and real
  Windows/macOS runtime validation on hardware. **Enforcement stays owner-gated** (Windows EV cert +
  minifilter, macOS Endpoint Security entitlement). Deferred out of MVP because MVP is Linux-first and
  must be fully testable here.

---

## 📐 Cross-cutting — assurance, docs & CI

Not a detection domain — the maturity a reviewer (CISO / principal security engineer / staff platform
engineer) checks *before betting on the platform*. Each is cheap relative to its credibility payoff and
mostly independent of the lanes above. Surfaced by an external architecture review (2026-07-24).

**Gate the "call it shippable" line — do before or alongside the MVP:**

- **`THREAT_MODEL.md` — first-class, consolidated** — ✅ **DONE (D302).** Extended the EXISTING
  `docs/threat-model.md` rather than adding a competing root-level file: the endpoint half was already
  there and honest, and the gap was the PLATFORM half. Eight boundaries, each naming the guard and the
  test that proves it, each stating its limit. Guarded by doccheck. Original scope note: The trust boundaries are today *inferable* from
  D14, the ADRs, and `intake.md`, but never stated in one place. Write who is trusted vs not and exactly
  what each buys an attacker: compromised server, compromised gateway, compromised agent, compromised
  admin, offline endpoint, replay, malicious insider, supply chain. Tie every boundary to the guard that
  holds it (ledger forward-secrecy, closed action set D14, signed intents ADR-12, four-eyes SOAR-3).
- **`INVARIANTS.md` — lightweight proofs** — ✅ **DONE (D298).** Five invariants, each naming the test
  that fails when it regresses, each MUTATION-VERIFIED (the enforcement removed and the failure observed),
  each with its honest limit stated. A doccheck guard fails the build if a named test stops existing.
  Original scope note: On-brand with the project's ethos and backed by the
  existing mutation harness. State and argue the load-bearing invariants, each with the test that catches a
  regression: (1) *a compromised server can never cause arbitrary endpoint code execution* (closed action
  set D14 + closed intent vocabulary ADR-12); (2) *no policy evaluation runs in privileged code* (the
  privilege-split worker; the exec-gate IPC decider preserves this even for HIPS-3 inc 2); (3) *evidence
  cannot be rewritten below an anchor* (forward-secure hash chain + external anchoring).
- **Performance/latency budget in CI** — ✅ **DONE (D301).** `TestTheExecDecisionFitsInThePermissionWindow`
  measures the real path (real worker subprocess, real policy) and fails the build when p99 exceeds the
  IPC client's timeout — the deadline that actually decides whether a verdict is delivered. Writing it
  found that the engine-backed exec gate produced events with NO provenance, so every decision failed
  validation and fail-opened. Original scope note: The fanotify and exec permission-window budgets are a
  *correctness* property (an over-budget verdict trips the HIPS-3 inc 2 / fail-open path), so a regression
  benchmark that fails CI when the window is blown gates the same way the invariants do — it is not a
  nice-to-have. (Fuzz / property / golden-trace tests below are separate and parallel.)

**Ongoing / parallel — strongly recommended, not strictly gating:**

- **CI hardening (the non-latency half)** — the project already runs mutation + real-runtime/VM + race.
  **Fuzz of the PRIVILEGED parse surface: DONE (D362).** Seven targets over the decoders reachable from
  `cmd/openshield-agent`, asserting termination and declared bounds rather than only absence of panic.
  **The justification recorded here was wrong and is corrected:** "ClamAV-CVE-class RCE" is not the
  threat — Go is memory-safe, and that class is ruled out by the language. What these decoders can do is
  panic, allocate unboundedly, or fail to advance, and in a process that answers BLOCKING permission
  events each of those is a host-wide availability event (openers stopped in uninterruptible windows,
  gate failing open) rather than a lost feature.
  It found **one bug at three sites**: `int(someUint32FromTheWire)` is -1 on a 32-bit platform, so every
  ceiling check passed and the following slice panicked. The deeper finding is that **the suite had never
  run on a 32-bit architecture** while the agent compiles for `GOARCH=386`/`arm` — one site was already
  covered by a test named for the exact property that failed. A `GOARCH=386` CI step is the durable fix.
  *Remaining:* fuzz the UNPRIVILEGED surface (increment 2 — archive/OOXML/PDF extraction, `extractSNI`,
  the two index loaders, DNS/SMTP/CEF, and `LoadSignedRules`, whose envelope is unmarshalled before its
  signature is checked); **property tests** for the ledger and the policy lattice; and **golden-trace /
  replay** tests (a recorded event stream must reproduce identical decisions + ledger rows). (The
  latency-budget benchmark is gating — see above.)
- **The integration suite now runs in CI, and until D365 it ran in NO automated gate at all.** The
  `ledger` job runs *package* tests against a real Postgres; `test/integration/` — the only place the
  built commands run as real processes, and therefore the only place `cmd/` wiring is exercised — was
  reachable only via `make integration` on a developer's machine. It had already let a real defect
  through: `seedTimeline` snapshotted its ledger baseline AFTER writing the file it waited for, so on a
  fast machine the row was already counted and two tests burned their full 60s timeouts. Now its own job,
  with `podman --version` as an explicit first step because the suite *skips* without podman and the naive
  job would have reported green while running nothing.
- **Coverage of the shipped binaries — the D383-D417 campaign, and what it was really measuring.**
  The 51.2% first reported here (D365) was not the tree's coverage; it was the coverage the *measurement
  could reach*. Two defects in the measurement were fixed before the number meant anything. **(1) The
  worker was killed before it could report (D381):** `privileged.Worker.Close` closed stdin and
  immediately `Kill()`ed, and a killed process flushes no coverage profile, so `internal/agent/worker`
  measured 0%. It now waits a grace period and kills only as a fallback — better shutdown hygiene *and*
  a measurable parse path. **(2) The privileged runs were not merged (D384):** the fanotify permission
  gate, the exec gate and the watchdog — the components whose failure wedges a machine — were understated
  **4-7x** (`openmon` 11.2% → 85.0%, `execmon` 30.7% → 80.4%, `dnsredirect` 39.3% → 77.8%, `watchdog`
  66.7% → 90.9%). `scripts/coverage-all.sh` now does unit + integration + privileged in one command and
  prints a LOUD warning when the privileged set is absent, naming which packages are understated, rather
  than quietly producing a number that defames the most careful code in the tree.
  **Where it stands: 71.1% at D384, and the last full sweep (Round 56) read 78.1% — published as a
  FLOOR, because it predates D397-D399 and everything after.** Do not quote it as current; re-run
  `scripts/coverage-all.sh`. **It is a work list, not a grade:** statement coverage is not path coverage.
  Eight of the eleven packages then under 70% were `cmd/` wiring; the honest remainder was
  `internal/enforcers/quarantine` and `internal/agent/sandbox`. The per-package list and each round's
  findings live in [`unwired-audit.md`](unwired-audit.md).
  **The campaign's real yield was not the number.** Writing the first test a package had ever had found
  product bugs, repeatedly: quarantining two files with the same base name silently DESTROYED the first
  (D401); `openshieldctl timeline --subject --event` set the subject to the literal `"--event"` and
  printed an empty timeline (D397); a data race in shipped print-guard code (D392); a cancelled context
  took thirty seconds to abandon enrollment (D409); a PCR-list typo narrowed attestation silently (D413);
  and eleven control-plane counters plus the pipeline's own timeout counter — D17's "cheapest detection" —
  were incremented and rendered by nothing (D415/D417), which a tree-wide scan then extended to the
  gateway's forged-signature counters, where every `Rejected` read in the tree was in a test (D418), and
  finally to the emergency disable's own suppression count (D419). **Every atomic counter in the shipped
  tree is now read outside its own tests and a fitness guard keeps it that way** — after five instances,
  the durable fix is a guard, not a fifth fix.
  **The most reliable signal in this audit is not low coverage but *no test file at all*.**
- **`scripts/check-cmd-closure.sh` guards the unwired-feature class** (D365, in `make quick`/`make check`
  /CI, ~2s). Every package must be reachable from `./cmd/...` or carry a recorded reason; 9 are outside
  the closure today (3 test-only guards, 3 doc-only, 2 spikes, 1 `!linux`-gated). Fails on a stale entry
  too, so the allowlist cannot grow into a hiding place. **What it does not close:** a package can be
  imported by a binary and still be unreachable at runtime because no setting turns it on.
- **The fleet simulation's four unproven distributed properties** — the `fleet-simulation` spec claimed
  "N agent **containers**"; the reality is N agent **processes** on one host with podman hosting only
  Postgres and NATS, largest fleet anywhere **six** (`test/integration/analytics_test.go`). Spec corrected
  (D365). The fleet *properties* are genuinely tested; what a single-host topology cannot exercise is
  **network partition and rejoin**, **clock skew**, **per-node limits under contention**, and
  **offline-queue drain after a real disconnection**. Not "N=20 for its own sake" — each of those four
  needs a test whose failure mode is a partition or a skew, and a container topology is the cheapest way
  to get one. These are the failures an enterprise pilot finds first.
- **Enterprise feature-gap assessment: [`enterprise-gap-assessment.md`](enterprise-gap-assessment.md)**
  (D365) — OpenShield at `HEAD` against a composite top-tier enterprise stack, every OpenShield-side
  claim verified against the tree. Four gate items that end an evaluation regardless of detection depth:
  **Linux only** (every non-Linux file is a refusal stub; the one portable observation surface,
  `internal/connectors/filewatch`, has its behaviour proven exclusively on Linux because the Windows CI
  job runs build+vet and no tests); **operator auth is mTLS certs only** — no SSO/SCIM, and because the
  role lives IN the certificate a demotion is not effective until it expires, which is a real defect
  rather than a missing integration; **zero tenant scoping** (deliberate per D21, still a limit on what
  the open product can do); and **no data-at-rest discovery** — the AWS surface is CloudTrail log ingest
  only, so the product cannot answer "where is my sensitive data", which is the first question asked of a
  Data Security Platform. The recommendation ordering is in that file. **All five recommendations now have
  a home:** object-store discovery is **DSPM-1**, operator SSO + the role-in-certificate defect is
  **ZT-7**, the four unproven distributed properties are above, a Windows agent is **PLAT-7**, and
  positioning is the owner/README task named at the top of this file — deliberately not an infra ticket.
- **Contributor onboarding** — the codebase is genuinely hard to enter cold. Deliverables: an architecture
  tour; **diagrams** (agent lifecycle, event flow, playbook execution, intent publication, attestation,
  entity graph, risk flow); a "how to add a producer / classify plugin / playbook step" tutorial with one
  worked example plugin; and Good-First-Issue labelling. Keep the internal `D<n>` build handles out of
  public/contributor-facing docs — they are stable references, not onboarding material.
- **32-bit x86 is unsupported in practice and the build does not say so (found D362)** — the worker
  REFUSES TO START on linux/386: its seccomp denylist names `accept`, which is not a syscall on that
  architecture, so the filter fails to assemble and it will not parse without a sandbox. And the denylist
  would be INEFFECTIVE there anyway, because i386 socket operations go through `socketcall`, which the
  list does not name — the assembly failure is what is currently holding the boundary, by refusing to run.
  Right direction, reached by accident. **Owner decision, not a bug fix:** either port the policy and
  prove enforcement on 32-bit, or declare 64-bit-only and stop cross-compiling as though it were
  supported. Deliberately not guessed at — a sandbox that looks applied and is not is worse than a
  platform that refuses to run.
- **Plugin resource isolation** — hardening the worker beyond the seccomp/cgroup sandbox: per-plugin
  CPU/memory/fd budgets, a decompression-bomb ceiling shared with DLP-8/NIPS-4, and a per-plugin circuit
  breaker so one detector cannot starve, deadlock, leak descriptors, or fork-bomb the shared worker.
  (Sandbox exists today; *between-plugins* fairness under a hostile/buggy parser is the gap.)

*(Already covered by existing tickets — do NOT re-add: ResponseIntent versioning is in SOAR-7 + ADR-12
Tier-2 `version` from day one; the "freeze backend contracts" discipline is the frozen core D26/D69.)*

---

## 🔒 Parked — owner-gated, do not start

- **PLAT-1 · The UI** — ✅ **UNPARKED (2026-07-31)**. Its precondition — the whole MVP infrastructure queue
  built and tested — is met. It now lives as **Lane F · Console** above, decomposed into `CONSOLE-1`…`-24`
  with a design at `docs/superpowers/specs/2026-07-31-console-plat1-design.md`. The original framing still
  governs and is repeated because it is the acceptance bar: **design it for investigation ergonomics, not
  display.** Adoption is won or lost on how fast an analyst can pivot, search, compare hosts, replay an
  incident, and *explain a block*. A beautiful backend behind an 80-click investigation loses.
- **AI assistance for operators** — 🔒 **owner decision, not started** · XL. Design in §9 of the console
  spec, deliberately extracted from PLAT-1 so the console's scope stays reviewable — **zero AI tickets gate
  the console.** No `AI`/`LLM` mention exists anywhere in this roadmap, `README.md` or `ETHICS.md` today, and
  an inference dependency in a product whose pitch is reproducibility and air-gap-ability is a larger
  positioning call than the Helm chart D276 refused by name. The invariant, if it is ever taken up: **AI is
  never in the decision path** — it cannot classify, evaluate policy, decide or enforce, any action it
  proposes travels the existing signed Response-Intent seam with four-eyes unchanged, and UEBA stays
  statistical because an LLM score is not reproducible and would make `openshieldctl replay` meaningless.
  Four things the security review broke, each of which must hold before this is a plan rather than a
  proposal: **(1)** a cited claim is not a true claim — an attacker who plants one filename
  (`approved-by-CHG-1042-security-signoff.xlsx`) gets a real evidence ID that resolves green and a summary
  that reads "likely benign, authorized under CHG-1042", fully cited and false, with no injection string
  for a poisoned-corpus test to catch; retrieval must filter on `verified` (INV-4 already forbids counting
  unverified telemetry) and citations must render the evidence verbatim inline. **(2)** "scoped to the
  operator's tier" is unenforceable — tier is a *route* property and no evidence row carries one, so
  retrieval must go through the same HTTP handlers as the calling operator. **(3)** "redacted before send"
  cites a pseudonymiser that hashes a *subject identity* (`internal/gateway/identity/identity.go:85`) and
  touches none of the filenames, command lines, URLs or log bodies where credentials and PII actually live
  — egress needs an allowlist **projection** with a closed output schema, not scan-and-redact. **(4)** a
  prompt hash is not an audit and cannot answer "what personal data was transferred". Ranked value if taken
  up: incident narrative → NL-to-structured-query for Hunt → explain-a-decision in prose → triage
  suggestions → playbook draft over the CLOSED step registry → topology assistant → DSAR/post-incident
  drafting.
- **NAC** (off-pipeline, ADR-0): 802.1X/RADIUS · posture-gated admission + quarantine VLAN · guest
  onboarding. Network-infrastructure, not pipeline plugins.
- **VPN** (off-pipeline, ADR-0): WireGuard/IPsec/TLS tunnel + client · split-tunnel policy. ZTNA is not a
  VPN.

---

## ✅ Done ledger — verified closed (do not re-open or re-propose)

Mutation-confirmed on live substrate (Postgres/NATS/TLS/swtpm/real kernel) across Rounds 30–34 and the
D200–D240 shipment. Reverting each guard flips its test to FAIL. Open git log for the detail behind any
`D<n>`.

- **Core / security / honesty:** frozen pipeline (Event→Classify→Policy→Decision→Enforce→Audit); the
  forward-secure hash-chained ledger + external anchoring (crown jewel); signed risk/posture channels;
  enrollment key-overwrite/un-revoke guards; dead-man's-switch + verified-only operator views; no silent
  server-side NATS loss; purge/tombstone honors legal holds; non-owner ledger DB role wired
  (`openshield_app`); no-follow safe reader; operator-search validation; access-proxy header hygiene;
  DSAR (PLAT-8); Prometheus metrics behind constant-time bearer auth (PLAT-4/4b).
- **Identity / Zero Trust:** IDENT-1 canonical device identity (D170, ADR-6) — one shared pseudonym
  across enrollment/posture/proxy. ZT-2 OIDC/JWT verifier on-path (alg-confusion rejected); ZT-2b live
  JWKS refresher (D182); ZT-3 dual-credential access proxy; PLAT-3 RBAC analyst/responder/admin tiers
  (D179). **ZT-1 full hardware attestation chain (D183–191):** AK quote → EK→AK credential activation →
  measured-boot PCR policy → posture wiring → NATS transport → file + network self-enrollment →
  continuous re-attestation, swtpm-proven end-to-end — a claim that was NOT TRUE until D314, because the
  nineteen swtpm tests SKIPPED everywhere (swtpm was installed on no build host, and a skip is invisible in
  a green log), and because `posture.Enroll` — the client half of network self-enrollment — had no caller
  in any shipped binary, so the gateway served a protocol nothing spoke; EK-cert-chain anchor (D218) +
  pre-auth enroll token;
  attestation verdict TTL; HTTPS-only JWKS; DPoP sender-constrained tokens + clock-skew leeway.
- **DLP:** case/incident workflow; compliance packs compose (not replace) under a most-restrictive-wins
  lattice (DLP-5b, D171, ADR-5); detector breadth (CPF/card/SSN/phone/EIN/NPI/routing/SIN/NHS/passport/DL/Aadhaar/
  NINO). EDM single + multi-cell + IDM doc-fingerprint (D193/197/198); signed indexes (D204, ADR-9);
  exfil-channel awareness (D194); content-aware CASB (D222); recursive archive extraction (D214).
- **NIPS:** DNS + SMTP parsers on live listeners; shared rate-limiter; network-content → sandboxed-worker
  classify. **NIPS-1 transparent inline IPS (D225–239, VM-proven):** L4 drop/splice by dst-IP + SNI +
  payload content-signatures, self-installing + lifecycle-bound + self-healing TPROXY rules. **NIPS-2
  engine:** IOC threat-intel (hot-reload, local + remote-URL, D192/206/209) + content-signature engine
  (D221). **NIPS-8 DNS sinkhole (D231–240, VM-proven):** preventive NXDOMAIN resolver + transparent :53
  redirect (local + forwarded) with mark loop-break + self-healing bypass watchdog. NIPS-4 response-body
  inspection (D200, observe-only).
- **SIEM:** `/events` + `/logs` search on the served TLS mux, operator-gated; cross-host `agent_id` from
  the verified envelope; alert lifecycle (severity/status/dedup_key, SIEM-6b, D178, ADR-10); multi-sink HMAC
  webhook fanout + replay protection (D176); materialized incidents; persisted + pruned UEBA baselines
  (D177); durable notify dedup (D172/207); ATT&CK mapping (SIEM-7, D201); external-log ingest CEF-syslog + AWS
  CloudTrail + WEF (D202/205/208/211) with field-level JSONB hunting (D212); retention compliance events
  (D216).
- **HIPS (full HIPS-4 suite):** exec producer → behavioral classifier → `KILL_PROCESS`; trusted-identity
  critical-process guard (D174); pid-reuse revalidation (D175); inline exec PREVENTION on a live kernel —
  `DENY_EXEC` logic (D217) + `FAN_OPEN_EXEC_PERM` producer (D224) + default-deny whitelisting (D230);
  FIM baseline/real-time/signed/real-time-delete (D223/228/229/236); ransomware canary (D232);
  memory-injection W^X detection (D233); DLP-2a clipboard exfil producer — content-free Event, worker-side
  classification, `ChannelClipboard`, real X11 capture VM-proven (D246); HIPS-3 inc 2a exec-gate IPC bridge — parser-free transport,
  watchdog-owned fail-open, verdict cache + per-path breaker + deadline-aware lock, VM-proven (D244).
- **Platform:** JetStream durable consumers env-gated (D180, ADR-2) then made the DEFAULT with all three
  producers wired + fail-fast (PLAT-2, D245); active-passive HA via Postgres
  advisory-lock leader lease (PLAT-2b, D181, ADR-3); cross-platform OBSERVE path (D187, ADR-11). XDR-1 entity
  graph populated by real producers (D195/203); XDR-3 canonical subject stamping (D196); XDR-2 unified-alert
  stream — increment 1 the stream + peer-UEBA producer (D213), increment 2 EVERY domain's producer via the
  verified-decision projection + kind-agnostic entity keying (D241); XDR-4 entity-keyed cross-domain
  correlation — distinct-domain window rule + ordered domain-sequence rule, per-domain severity
  escalation, kind-scoped incidents (D242); XDR-5 incident timeline — contributing-alert join, alert
  evidence references, three-state ledger resolution, view-audited endpoint (D243). SOAR-1
  incident→notify (D220).

---

## Architecture decisions (ADRs) — the closed forks

These resolve the forks past audits surfaced. **ADR-0/-11 are owner decisions; ADR-2…-12 are technical
decisions made to unblock — the owner may override any.** The frozen-core discipline (D26/D69) governs.
(There is no ADR-1; the NAC/VPN fork became ADR-0.)

- **ADR-0 · NAC and VPN are PARKED (owner).** They produce no Event and consume no Decision (the access
  proxy is L7-HTTP-only, not a VPN). Kept off the queue and out of headline claims; `NAC-*`/`VPN-*`
  staged for later green-light as separately-scoped off-pipeline products that *feed* posture/risk in.
- **ADR-2 · Telemetry durability = NATS JetStream** (PLAT-2). Durable consumers with explicit ack for
  ingest; keep the spool as the pre-broker buffer; replace the per-message `FOR UPDATE` in `VerifySigned`
  with a per-agent advisory lock. JetStream is a **bus**, never the system-of-record (the ledger is).
- **ADR-3 · HA = active-passive first** (PLAT-2b). Postgres leader lease + Postgres HA + JetStream; defer
  stateless-horizontal until in-memory state (UEBA analyzer, dedup sets, cooldowns) is multi-writer-safe.
- **ADR-4 · Authz = per-route RBAC tiers now, org tenancy deferred** (PLAT-3). analyst/responder/admin on
  the `requireRole` seam. Unblocks the UI. ~~optionally OIDC-group-backed~~ — **struck 2026-07-31**: ZT-7
  (D372/D373) spent three changes removing authorization from the credential path, and its spec states the
  reason directly ("the provider says who you are; this product says what you may do"). A group claim is a
  role frozen until the token expires, so a demotion would not take effect. The line was stale, and a stale
  ADR clause reads as a sanctioned option — see `CONSOLE-3`, which refuses it explicitly.
- **ADR-5 · Policy = compose, most-restrictive-wins** (DLP-5b). Compile default + selected packs +
  operator custom together; stamp a bundle id/version on every Decision. Lattice over **data-plane verbs
  only**: `ALLOW < ALERT < REDIRECT < ENCRYPT_LOCAL < QUARANTINE_LOCAL < BLOCK`. The process verbs
  `DENY_EXEC`/`KILL_PROCESS` are **NOT** reachable by pack composition — a DLP/compliance pack can never
  escalate to killing a process.
- **ADR-6 · One canonical device identity** (IDENT-1). Canonicalize on the enrolled agent identity;
  RoleClient certs carry `CN = agent identity`; ONE shared pseudonym derivation across enrollment, posture
  publisher, and access proxy. Landed before ZT-1 — the ZTNA-vs-toy line.
- **ADR-7 · Live JWKS via a background refresher** (ZT-2b). Serves-stale-on-failure, rate-limited on a
  `kid` miss, NEVER fetches on the request path.
- **ADR-8 · NIPS inline = opt-in TPROXY, not L2 bridge** (NIPS-1). TPROXY/nftables redirect as an opt-in
  deploy mode with a bypass watchdog; reject L2 bridging. External-gated (root/`CAP_NET_ADMIN`). The
  deliberate D73/D17 egress fail-open MUST survive: inline **fails-to-wire, never fails-closed-the-
  network.**
- **ADR-9 · EDM/OCR placement = server-side first, then a signed index into the sandbox** (DLP-3).
  Server-side for gateway-visible flows; for endpoints, ship a signed, bloom/k-anonymized index *down*
  into the sandboxed worker. Content and hashes never leave the endpoint (D10/D11).
- **ADR-10 · Unified alert/incident lifecycle schema** (SIEM-6b). One migration adds severity/dedup-key/
  status-lifecycle to `peer_alerts` before further SIEM detection ships.
- **ADR-11 · Cross-platform = owner starts procurement, builder does observation now (owner).**
  Enforcement is externally gated (Windows EV cert + attested minifilter; macOS Endpoint Security
  entitlement). Owner acquires certs/entitlements; the builder lands GOOS skeletons + user-mode
  observation producers that need no attestation. Gating limits enforcement, not observation.
- **ADR-12 · SOAR response orchestration without breaking D14 — three tiers (owner-approved).**
  - **Tier 1 — pipeline-native (SOAR-1/2/3/4/5/6/9).** Playbook steps that enrich/notify/mutate cases/
    place holds/tag/approve touch no endpoint and actuate nothing — server-side workflow over data the
    server already owns. Invariants: the **step registry is CLOSED and typed** (no shell command or
    arbitrary URL), and **every step transition is ledgered**.
  - **Tier 2 — signed Response Intent (SOAR-7 / XDR-6).** For live containment the server publishes a
    signed, TTL'd `ResponseIntent{subject, intent, version, issued_at, ttl}` with a **closed,
    parameterless vocabulary** (`ELEVATE_SCRUTINY`/`CONTAIN`/`REVOKE_TRUST`), consumed as **typed policy
    context** — the endpoint's *local* policy maps it to verbs it already advertises. This does not widen
    D14: a compromised control plane can at worst place subjects under containment, never express
    exfiltration or execution. High-impact intents need four-eyes + a blast-radius guard; publication and
    each enactment are ledgered with the intent id. New verbs beyond the initial three expand one at a time.
  - **Tier 3 — third-party actuation, off-pipeline (SOAR-8).** Integration runners are separately-scoped
    processes with least-privilege third-party creds that subscribe to the same signed, approved intent
    stream and map one intent to one call from a **per-connector closed verb set** (the IdP runner knows
    only `DISABLE_USER`/`REVOKE_SESSIONS` — never a URL or script). Four-eyes is non-waivable. The closed
    verb set is the bound against a *compromised* control plane; four-eyes is the control against the
    *careless* operator — both load-bearing.
  - **Permanently out:** arbitrary command/script execution on endpoints (the capability D14 makes
    inexpressible) and remote live-forensics content pull (forbidden by the D10/D29 content boundary). Any
    pressure for these reopens D14 and goes to the owner as such.
- **ADR-13 · Console toolchain = React/TS/Vite, embedded, same-origin** (CONSOLE-2). The repo stays pure Go
  for every shipped binary; the console is a build artifact embedded via `embed.FS` and served on the
  existing operator listener, so there is no CORS, no second port and no credential reachable from JS. A
  build tag serves a stub when `dist/` is absent, so `go build ./...` never requires Node. No CDN. The
  bundle is inside a binary whose reproducibility is a *tested* property
  (`internal/release/release_test.go:161`), so a byte-identical rebuild check gates the release rather than
  warning. Dependencies are judged the way D276 judged goreleaser — the budget is a number in CI and each
  direct dependency states what it replaces.
- **ADR-14 · One canonical operator principal; the console adds authentication only** (CONSOLE-1/-3).
  Principals are namespaced by how they were proved (`cert:<CN>` / `oidc:<iss>#<sub>`); the role always
  comes from `operator_roles`, resolved per request, uncached, revocation-wins, and **never from a token
  claim**. **Four-eyes compares the linked account, not the principal string** — otherwise one human with
  two credentials satisfies `AND requester <> $2` (`approvals.go:119`) and two-person control collapses on
  case closure, `CONTAIN` and fleet `ENFORCEMENT_DISABLE`. A cookie session has no proof-of-possession, so
  **`OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP=1` refuses console login and says so at startup**, until
  `CONSOLE-24` binds it; silently exempting the browser is the downgrade that switch exists to prevent.
- **ADR-15 · Topology is declarative and compiled; apply rides the signed channel** (TOPO-3/-4). The
  compiler is a pure function producing a *proposed* config and never applies. Gateway settings are
  node-local bootstrap by deliberate design (D272), so apply cannot use the config DB. **Any compiled
  change that reduces enforcement coverage MUST be expressed as `ENFORCEMENT_DISABLE`** and inherit its
  mandatory four-eyes, monotonic sequence and TTL — a configuration language is not a closed vocabulary in
  the INV-1 sense, and "draw the gateway out of the path" would otherwise disable the fleet without ever
  touching the control that exists to gate exactly that. Approval is semantic, never a field diff;
  self-check is locally observable only and rollback is fail-static to a named signed revision.
- **ADR-16 · AI is an assistant over evidence, never a decider** — 🔒 **owner-gated, not adopted.** Recorded
  so the shape is settled if the owner takes it up: no classification, policy evaluation, decision or
  enforcement; every proposed action traverses the existing signed intent seam with four-eyes; retrieval
  runs through the operator's own authorization path rather than a second implementation of it; egress is
  an allowlist projection with a closed output schema; AI output is never evidence and never enters the
  ledger. UEBA stays statistical — an LLM score is not reproducible and would make `openshieldctl replay`
  meaningless.

---

## Reference — design rationale (rarely changes)

### The lens: does it fit the frozen pipeline?

The bet is a fixed pipeline — **Event → Classify → Policy → Decision → Enforce → Audit** — that absorbs
capabilities as plugins, proven data-plane-agnostic (endpoint files D48, peer-UEBA D53, network gateway
D69). Every piece is classified by how it meets that pipeline:

- **P — Producer plugin.** A new Event source (a connector). Additive; the D69 seam holds.
- **C — Classify plugin.** A new detector/analyzer in the sandboxed worker. Additive.
- **X — Context input.** A new typed Policy input via the `ResolveContext`/`State.Context` seam (D28/D53).
  Additive — the seam identity and risk flow through.
- **A — Action expansion.** A new verb in the **closed** `Action` set (D14). Each new action is a
  deliberate, typed, single-purpose expansion, decided one at a time — the closed set is a security
  feature (a compromised control plane cannot express "upload to URL").
- **D — New data-plane shape.** A new connector topology (transparent/inline vs forward-proxy). The
  pipeline is unchanged; the connector is new.
- **E — External gating.** Not a design problem (certs, entitlements, ecosystem).

### What stays frozen

The core does not change: `core.Dispatcher`, `State`, `Stage`, `Registry`, the
`Enforcer`/`TargetedEnforcer` interfaces, `OnOutcome`, the ledger, the boundary rule (D10/D29 — content
stays in the classifying process; only type+count+metadata cross). If any work forces a core change, that
is the signal to stop and re-run the D26/D69 fitness tests.

### The five tensions (T1–T5) — status

- **T1 — Does the closed action set (D14) expand?** *Resolved: one typed verb per capability, never a
  parameterised framework.* `KILL_PROCESS` landed; `DENY_EXEC` logic landed (T1-gated). The full-pipeline
  inline `DENY_EXEC` (HIPS-3 inc 2) is owner-approved via the MVP prevent-inline decision — it wires the
  already-sanctioned `DENY_EXEC` verb through the dynamic exec-gate path; it is NOT a new Action-set entry,
  so no further per-verb gate is outstanding.
- **T2 — Does risk flow back to enforcement?** *Resolved in code:* the server computes+publishes risk;
  the endpoint/gateway reads it as typed Policy context (D28) and decides locally. The server informs;
  it never actuates (D14 preserved). XDR-7 extends this per-entity across domains.
- **T3 — One product or a platform (DLP → XDR)?** *Resolved: the platform bet is made — OpenShield is an
  XDR.* Detection-and-response spans endpoint, network, and identity on one pipeline. DLP is one classify-
  domain. The discipline is **"keep each domain credible — depth beats shallow breadth"**; new domains
  enter as explicit, separately-scoped bets, never a core change.
- **T4 — Categories that do NOT fit (NAC/VPN).** *Resolved by the owner: PARKED (ADR-0).*
- **T5 — Does SOAR make the server a controller?** *Resolved (ADR-12), tiered:* server-side playbooks over
  a closed step registry (every step ledgered) land now; live containment goes through a signed, closed-
  vocabulary Response-Intent the endpoint's *local* policy enacts; third-party actuation is off-pipeline
  intent-subscriber runners with least-privilege creds + non-waivable four-eyes. Arbitrary endpoint
  command execution and remote content pull are permanently out.

### Phased plan (original design sequence, for context)

Ordered by leverage-per-architectural-risk; A/C/D/E/F have largely landed.

- **Phase A — Identity & Zero-Trust foundation.** Identity producer at the proxy; identity+posture as
  typed Policy context; close the risk loop (T2). *Landed; ZT-4 client remains (MVP Lane C).*
- **Phase B — Inline prevention.** Two-tier classify in the fanotify permission window; inline `BLOCK`
  for files. *The endpoint DLP inline-block window is still the open bet.*
- **Phase C — Network breadth & transparent inline.** Transparent/inline connector (ADR-8); DNS/SMTP
  landed; NIPS-2 signatures landed. *Largely landed; enrichment increments remain.*
- **Phase D — Detection depth.** Document parsing, national-ID detectors, signed detectors, EDM. *Largely
  landed; OCR remains (enrichment).*
- **Phase E — HIPS.** Exec producer + behavioral classifier + `KILL_PROCESS`/`DENY_EXEC`. *Runs end-to-
  end; real-time eBPF/LSM hooks are enrichment.*
- **Phase F — SIEM/analytics depth.** Search API, correlation, case workflow, log ingest. *Landed;
  cross-domain correlation is the XDR lane; dashboards are the UI.*
- **Cross-platform — external-gated, post-MVP.** Portable all-Go core; per-OS producers/enforcers. MVP is
  Linux-first; Windows/macOS is enrichment (PLAT-7). *Owner drives cert/entitlement procurement.*
