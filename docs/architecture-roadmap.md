# OpenShield architecture roadmap

> Companion to [`decisions.md`](decisions.md). This file holds the **forward plan**: what
> OpenShield is today, the **MVP cut** (everything required before the UI), the **enrichment
> backlog** (post-MVP plugins on the frozen core), and the **design rationale** as reference.
>
> **Authoritative status is this file at `HEAD`, current through D255.** History (round-by-round
> audits, the R34 findings, per-ticket shipment notes) lives in git and the session memory — it is
> not re-carried here. The compact *Done ledger* below records what shipped so it is not
> re-proposed; open git log for the detail behind any `D<n>`.

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

## What OpenShield is (status at a glance, through D255)

**OpenShield is architected as a pipeline-native XDR + SOAR** — one
Event→Classify→Policy→Decision→Enforce→Audit pipeline spanning **endpoint, network, and identity**, with
correlation, case/incident workflow, and a tamper-evident hash-chained evidence ledger above it. DLP is
one detection domain, not the center of gravity. The per-domain detection planes are now broadly real
and deep in several domains (hardware attestation, EDM/IDM, threat-intel + content-signature IPS, the
full HIPS-4 endpoint-behavioral suite, transparent inline network prevention). **The remaining frontier —
and the whole of the MVP queue below — is cross-domain correlation depth, SOAR orchestration + live
response, a ZTNA client, and packaging: turning a set of strong detectors into one coherent,
deployable, correlated product. The UI comes after all of that is built and tested.**

**Why OpenShield, in one sentence (a thesis the MVP must *earn* — not yet a proven claim):** *every
security decision — detection, correlation, and response — is explainable, reproducible, and
cryptographically auditable, on one incident timeline across endpoint, network, and identity.* Lead with
that; "pipeline-native XDR" is the engineering, not the pitch. Product positioning is currently thin — a
named gap, but an owner/README messaging task (it needs the product's voice, not a builder's), deliberately
NOT an infra ticket and not part of the queues below.

| Category | Maturity | One-line reality |
|---|---|---|
| **XDR** (umbrella) | ~80% | Entity graph WIRED and populated by real producers (device⋈user, D203); the entity-keyed `unified_alerts` stream is fed by **every** domain (D213/D241); and it is now **correlated cross-domain** — a distinct-domain window rule + an ordered domain-sequence rule grouped by `entity_id`, severity boosted per domain, materialized per entity and paging once (D242). incidents now carry a cross-domain **timeline** — contributing alerts in detection order, each linked to its evidence with an explicit resolved/unresolved/derived state, and reading one is view-audited (D243). **MVP gap:** coordinated response (XDR-6, needs SOAR-7 + HIPS-3 inc 2), per-entity risk aggregation (XDR-7). |
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

## 🔴 MVP infrastructure — the required queue

Work the five lanes below. Within a lane, top-to-bottom. Lanes can interleave where dependencies allow.
Each ticket names the ADR it implements where one applies, and its `Accept` is the real-path test that
closes it.

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
- **PLAT-9 · Operational lifecycle & recovery** — 🟡 **emergency disable (D265), verified restore (D266)
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
  **Still to do:** the question a CISO asks first — *how do I run
  this?* — and today the roadmap answers only "packaging." Deliver: rolling agent + server upgrade with
  version-skew tolerance and **rollback**; a fleet-wide **emergency disable** ("stop enforcing now") that
  fails safe and is itself ledgered; **backup + verified restore** of the Postgres system-of-record and the
  per-agent ledger (restore must re-verify the hash chain + anchors, not just the bytes); node/DB recovery
  + a basic DR runbook; and a documented **deployment footprint** (this is a compose/systemd/single-Helm-
  release product, not a 50-node cluster — state it, so operators can size it). *Accept: an upgrade rolls
  forward and back with no ledger gap; a restored backup re-verifies its chain + anchors; emergency-disable
  flips the fleet to observe-only within one interval and writes a ledger entry.*

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
- **ZT-5 · Policy admin + session recording** — new work · L. Ties to the UI (PLAT-1).
- **ZT-7 · Operator SSO, and the role must leave the certificate** — ✅ **DONE (D372 + D373)**: the DEFECT is
  fixed (D372) and operator SSO ships (D373). The role now lives in `operator_roles` and is resolved server-side per
  request, so a demotion or a revocation takes effect on the operator's next request instead of when their
  certificate expires — there was previously no way to remove an operator's access at all. Revocation is a
  ROW, not a delete (a delete would fall back to the certificate and RESTORE the embedded role); a database
  error DENIES rather than falling back (fail-open is right for enforcement per D17/D18 and wrong for
  authorization); `agent` is not a grantable operator role, so one compromised endpoint is not a compromised
  console; no cache, because a TTL sells back the immediacy this buys. `openshield-server operator-role
  set|revoke|list` is operator-local (D51). Migration path: no row → the certificate still decides and the
  server says so once with the fixing command; `OPENSHIELD_OPERATOR_ROLES_STRICT=1` refuses that, and is the
  intended end state.
  **D373 — SSO, and the decision it rests on:** an operator may present an OIDC bearer token instead of a
  certificate, and **the token's claims do NOT decide the role**. Mapping an IdP group to a tier is the
  conventional design and it reintroduces exactly what D372 removed, with a shorter fuse — a token issued
  before a demotion still asserts the old group until it expires. The IdP says who you are; the product says
  what you may do. Consequence: an SSO operator has no certificate and therefore no embedded role to fall
  back to, so they are **strict by construction** while certificate holders migrate. `verifyCore` is
  extracted so the operator path shares every fail-closed JWT check with the ZTNA path rather than
  duplicating six of them; the subject is raw rather than pseudonymised, because an operator is not the
  monitored population and an unattributable action is not evidence.
  **D375 — and operator SSO shipped UNUSABLE until it.** The control plane's HTTP surface is mutual TLS with
  `RequireAndVerifyClientCert`, so an SSO operator — who by definition has no certificate — was refused at
  the handshake with `tls: certificate required`, before the bearer token was ever read. The feature could
  not run in any deployment. An INTEGRATION test found it; the package tests could not, because they drive a
  handler with a synthesised TLS state. Fixed with `VerifyClientCertIfGiven` scoped to SSO-enabled
  deployments — a presented certificate is still verified, only absence stops being fatal. The assertion
  guarding that ("an untrusted certificate is still refused") was itself VACUOUS at first: a client from a
  second PKI fails the handshake client-side, so it passed against a mutant with no server-side verification
  at all. See the change's design notes — when asserting one side rejects something, the other side must
  have no reason to fail.
  **STILL OPEN:** **SCIM** — deprovisioning is a manual `operator-role revoke`, so an IdP deactivating a
  user bounds exposure to a token lifetime rather than removing authority; **no JIT provisioning**, so a
  first-time SSO operator has no access until an admin grants it; **DPoP on the operator path: ✅ DONE (D379)** — a token carrying `cnf.jkt` needs a proof of possession bound to the method and URI, single-use and fresh; a bound token reaching a verifier that cannot check proofs is REFUSED rather than downgraded; `OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP` refuses UNBOUND tokens (off by default — on before the issuer binds locks everyone out). *Residual:* `htu` is built from the Host header, so a proxy that rewrites it breaks proofs; replay rejection is bounded by a cache; four-eyes on a
  grant; and certificate revocation proper — revoking authorization leaves the identity able to
  authenticate, just unable to do anything. Two things, and the
  second is a DEFECT rather than a missing integration. Operator identity today is mTLS client certs only
  (`tlsconf` sets `RequireAndVerifyClientCert`) with the RBAC tier carried IN the issued certificate
  (`internal/provision/provision.go` — `RoleAnalyst`/`RoleResponder`/`RoleAdmin`, ordered by
  `internal/controlplane/views.go`). There is no SAML anywhere in the tree, and the only OIDC
  (`internal/gateway/identity`) authenticates ZTNA *subjects* through the access proxy — **not operators**.
  - *The checkbox:* enterprise IAM gates on SSO + SCIM deprovisioning. "We issue you a certificate" fails
    procurement regardless of being cryptographically better, because the control being bought is
    centralised joiner/mover/leaver.
  - *The defect:* because the role is IN the cert, a demotion is not effective until it expires or is
    revoked. There is no "revoke this analyst's responder rights now" primitive. For a product whose
    thesis is an auditable decision record, an authorization change on a certificate-lifetime delay is a
    hole. **Fix this first — it is a prerequisite for SSO anyway**, and it is worth doing even if SSO
    never ships.
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
- **Coverage of the shipped binaries: 51.2% of statements**, 82 packages, one integration run
  (`scripts/coverage-integration.sh`, D365). 6 packages at 0%, 10 under 25%. Four of the zeros are
  root/display-gated and covered on the VM; one — `internal/connectors/rfc5424` — was a REAL gap now
  closed (every syslog scenario in the suite sent CEF, so the RFC 5424 fallback could not be reached by
  any configuration the suite produces); and one is a limit of the measurement, below. **51.2% is a work
  list, not a grade:** statement coverage is not path coverage, and the number understates the truth by
  an unknown amount for the reason in the next bullet.
- **`privileged.Worker.Close` SIGKILLs the worker, so the parse path cannot be coverage-measured** — it
  closes stdin and then immediately calls `cmd.Process.Kill()`, and a killed process flushes no coverage
  profile. `internal/agent/worker` therefore measures 0% while `cmd/openshield-worker` measures 48.2%
  (startup paths from workers that raced to exit on stdin EOF first). Closing stdin, waiting briefly, then
  killing would be better shutdown hygiene *and* would make the measurement possible — but changing
  production shutdown semantics to improve a metric needs its own reasoning, so it is a ticket, not a
  side effect. Small; worth doing.
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

- **PLAT-1 · The UI** — XL — *the single biggest enterprise-credibility gap, and deliberately last.*
  Minimal SPA (or rich TUI first) over the operator-read API: fleet health, alerts, incidents, search,
  agent status, cases. Needs a frontend-toolchain decision (repo is pure Go). **Starts only after the
  entire MVP infrastructure queue is built and tested.** Its authz model is already unblocked by ADR-4.
  **Design it for investigation ergonomics, not display.** Adoption is won or lost on how fast an analyst
  can pivot, search, compare hosts, replay an incident, and *explain a block* — not on how the backend
  looks. Treat pivot / search / replay / explain-a-decision as first-class PLAT-1 requirements, measured in
  clicks-to-answer. A beautiful backend behind an 80-click investigation loses.
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
  the `requireRole` seam, optionally OIDC-group-backed. Unblocks the UI.
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
