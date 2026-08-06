# OpenShield architecture roadmap

> Companion to [`decisions.md`](decisions.md). This file holds the **forward plan**: what
> OpenShield is today, the **MVP cut** (everything required before the UI), the **enrichment
> backlog** (post-MVP plugins on the frozen core), and the **design rationale** as reference.
>
> **Authoritative status is this file at `HEAD`, current through D472.** History (round-by-round
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

## What OpenShield is (status at a glance, through D472)

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

**What has actually been shipping since (D440–D469), and why it is not the UI.** Two threads, both
deliberate. The first is *enrichment on the frozen core* — release verification, endpoint self-posture,
fleet binary provenance, Spanish/French national IDs, bucket access context for data-at-rest discovery,
and the ATT&CK technique lane through the Decision contract into correlation. The second, and the more
valuable one, is **the unwired-feature hunt**: a mechanical scan for exported fields assigned only in
tests, which found capability after capability that was implemented, tested, and reachable by nothing.
`Sequence`/`TechniqueSequence` (D456) could be *asked about* and never reported, because the scheduled
correlation loop never set them. `core.ExclusionSet` (D457) — the privacy exclusion primitive the DPIA
template tells deployers to record — had **zero non-test callers**. And chasing one of those leads found
D458: two producers ran the pipeline twice over ONE-SHOT content, so a print verdict could be decided by
the run that saw nothing, and allow. **This is the highest-yield activity in the repo right now**, and
running it to exhaustion before the UI is the right order: a console that displays an inert control is
worse than no console. The scan and its still-open leads are in session memory.

**Why OpenShield, in one sentence (a thesis the MVP must *earn* — not yet a proven claim):** *every
security decision — detection, correlation, and response — is explainable, reproducible, and
cryptographically auditable, on one incident timeline across endpoint, network, and identity.* Lead with
that; "pipeline-native XDR" is the engineering, not the pitch. Product positioning is currently thin — a
named gap, but an owner/README messaging task (it needs the product's voice, not a builder's), deliberately
NOT an infra ticket and not part of the queues below.

> **The denominator, stated once.** These percentages are a self-assessment against **the scope this
> project set for itself**, not against a commercial product in the category. A domain at 80% here has
> the depth its own design called for; it does not have the integration catalogue, the console, or the
> field hardening a buyer compares it to. `enterprise-gap-assessment.md` is the buyer's view and is
> deliberately less flattering. Re-assessed at D460 — several numbers came DOWN, not because anything
> regressed, but because they had been measured against an unstated and flattering denominator.

| Category | Maturity | One-line reality |
|---|---|---|
| **XDR** (umbrella) | ~75% | Entity graph WIRED and populated by real producers (device⋈user, D203); the entity-keyed `unified_alerts` stream is fed by **every** domain (D213/D241); and it is now **correlated cross-domain** — a distinct-domain window rule + an ordered domain-sequence rule grouped by `entity_id`, severity boosted per domain, materialized per entity and paging once (D242). incidents now carry a cross-domain **timeline** — contributing alerts in detection order, each linked to its evidence with an explicit resolved/unresolved/derived state, and reading one is view-audited (D243). Coordinated cross-domain response (XDR-6, D254) and per-entity risk aggregation (XDR-7, D255) both landed — **Lane A is complete.** **Remaining gap is the operator surface:** there is no analyst UI to read a timeline in, and the CLI/API are the interface (PLAT-1, parked and deliberately last). |
| Zero Trust (ZTNA) | ~80% | Full hardware attestation chain (ZT-1, swtpm-proven end-to-end: TPM quote → EK→AK activation → measured-boot PCR → continuous re-attestation → network self-enrollment; EK-cert anchor + pre-auth enroll token + attestation TTL + DPoP-bound tokens). Live JWKS refresher, RBAC tiers, dual-credential access proxy. The endpoint half now exists: an agent-brokered client presents the DEVICE certificate to the access proxy, refuses to start without an identity, binds loopback only and never falls back (ZT-4, D249). **D427 closed half the "HTTP(S) only" gap:** a `tcp://host:port` catalogue entry is reached by CONNECT on the SAME mutually-authenticated connection, so a database or SSH host inherits the device certificate, the OIDC user, posture and risk without a second auth path — *"a Zero-Trust gate with a VPN next to it is a VPN."* **D428 closed "does not PREVENT bypass", on the endpoint half:** the agent fences the host so traffic to protected ranges is REJECTED except to the gateway, rejections counted, proven on a real kernel. **ZT-12 then closed the last two named residuals:** a mutually-authenticated **SOCKS5** listener carries the device credential with an access ticket for the user one (CONNECT only — BIND and UDP ASSOCIATE refused), and **split-horizon DNS** answers an internal name with the address a client should actually be sent to. **Residual:** the NETWORK half — the protected network accepting only the gateway — lives outside the product; **SAML and JIT provisioning are absent**, and the SCIM subset has never run against a live IdP; no continuous posture re-evaluation *inside* a long-lived tunnel. |
| DLP | ~75% | Deep content detection: EDM single/multi-cell + IDM doc-fingerprint + exfil-channel awareness + keyword-proximity + national IDs, all boundary-honored; signed indexes (ADR-9); recursive archive extraction; content-aware CASB blocks sensitive uploads to unsanctioned clouds. Clipboard is now MEDIATED on X11 — the engine owns the selection and DECIDES each paste per destination (source→destination, enforced, VM-proven with a real cross-process paste refused), with password-manager exclusions applied before the read (D246/D247). Wayland stays observe-only: its protocol cannot identify a paste's destination. PRINT is intercepted in the CUPS filter chain and a sensitive job is ABORTED before it prints (DLP-2b, D248, proven on a real spooler). **Lane E DLP work is complete for the MVP.** **Enrichment:** OCR, screenshot, CASB refinements. |
| NIPS / NTPS | ~75% | Real inline IPS: transparent TPROXY drops/splices L4 by dst-IP/SNI/payload and self-installs + self-heals its rules (VM-proven); threat-intel IOC engine + content-signature engine (hot-reload, local file or remote URL); DNS preventive sinkhole with transparent :53 redirect (local + forwarded) + bypass watchdog (VM-proven). **D429 added JA3** — computed from the same peeked bytes as the SNI (one peek, two signals), accepted as an IOC kind, GREASE excluded (without which the same client fingerprints differently every connection and the feature looks correct while never matching), and **reported at 0.8 against a destination match's 1.0 because a JA3 identifies a TLS library shared by every program built on it — evidence, not proof.** Its parser walks attacker-controlled length fields on the hot path in a non-privilege-separated process, so it is bounds-checked and `FuzzJA3` is in CI. **HTTP/2, QUIC (NIPS-12) and SMTP *filtering* have since shipped** — all three through the same pipeline, which is the point of the architecture. **Enrichment gap:** a full Suricata-compatible rule grammar; today's IOC feed is a flat `<kind> <indicator>` format, not a rule language, so an operator cannot bring rules they already have. |
| SIEM | ~70% | Alert lifecycle unified (severity/status/dedup, ATT&CK mapping, durable notify dedup, pruned baselines); external-log ingest live (CEF-syslog + AWS CloudTrail + WEF Windows-XML) with field-level JSONB hunting via `GET /logs`. **D425 closed cross-vendor field normalization** (one hunt, every vendor's field name), **D426 saved searches** (SIEM-14, a hunt the whole team can run rather than one analyst's shell history), **D435/D437 LEEF** on the listener that already speaks CEF. **Native Sysmon** joined CEF/LEEF/syslog/CloudTrail/WEF/NDJSON. **Enrichment gap:** no console (search is an API); retention and index management are basic next to a mature SIEM; scheduled reports (`CONSOLE-31`). |
| Privacy / data protection | ~80% | Pseudonymous subjects + purpose tags by default; type/confidence/count classification that never carries content or a reversible hash of low-entropy PII; retention purge that tombstones (chain stays verifiable) and refuses to erase what a legal hold covers; view-audited investigations; DSAR export; the four-eyes gate; a shipped DPIA template. **PRIV-1 (D457) wired the exclusion set**, which had been a correct predicate with no caller and no config key while the DPIA template told deployers to record it. **Honest limits:** a path exclusion needs resolved paths and is COUNTED when it cannot be evaluated (`privacy_exclusions_unevaluable`) rather than silently applied or silently skipped; an exclusion never suppresses an enforcement verdict, or it would be the user-invokable evasion the requirement forbids; an excluded subject is not PROTECTED either; no per-user/group exclusions, because there is no directory integration and a pseudonymous subject cannot be mapped to a person at the endpoint. |
| UEBA | ~30% | Peer-relative **count**-deviation detection with persisted, pruned baselines (D177) feeding entity risk. `ueba_baselines` is `subject → (count, last_seen)` — one number per subject — and alerting is a bare threshold (`signed.go:166`). **Honest limits, because the acronym promises more than the engine does:** no minimum-sample or warm-up gate, so a subject observed once can deviate (`UEBA-1`); no decay, no seasonality, no multi-feature profile, no inspectable peer-group model (`UEBA-2`); and **no operator surface at all** (`CONSOLE-53`). Stays statistical by decision — a model score is not reproducible, and `openshieldctl replay` would stop meaning anything. |
| HIPS | ~85% | Full HIPS-4 suite shipped + inline exec PREVENTION on a live kernel: static `DENY_EXEC` (deny-list/whitelist) + `FAN_OPEN_EXEC_PERM` producer + default-deny whitelisting (VM-proven); FIM (baseline/real-time/signed/delete), ransomware canary, memory-injection detection; trusted-identity critical-process guard + pid-reuse revalidation. The exec gate now gets its verdict from the FULL PIPELINE over a parser-free IPC bridge, VM-proven (D244, inc 2a). The intent-driven half is DONE too: a `CONTAIN` Response-Intent makes the entity's next exec kernel-REFUSED via a real OPA policy, VM-proven (D253). **The endpoint half of coordinated response is complete.** **Enrichment:** eBPF/LSM real-time hooks, JIT W+X allowlist, per-process ransomware attribution. |
| **SOAR** | ~80% | A case+notify shell with the notify gap closed (SOAR-1, D220: a materialized incident pages once, automatically). Correlation runs on a CLOCK (leader-only) and incidents carry a forward-only attributed lifecycle open→acknowledged→triaged→contained→closed (SOAR-2, D250). The control plane now ACTS: a declarative playbook over a closed, non-actuating step registry runs first response automatically and resumes across a restart without duplicating a step (SOAR-4, D256). Threat intel is real: signed feed ingest into a shared IOC store, and incidents are enriched from observables the verified events already carry (SOAR-5, D257). Response time is measured — detection latency, MTTA and MTTR, each reported with the population it excludes (SOAR-6, D258) — and notifications are ROUTED by kind/severity to named sinks, with a pending approval finally paging a human (SOAR-9, D259). An approved intent is ENACTED against an external identity provider with four-eyes re-checked by the runner (SOAR-8b, D260), and incidents sync bidirectionally with a ticketing system (SOAR-8a, D261). **LANE B IS COMPLETE.** |
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

**Every ticket in lanes A–E has shipped.** The sole remaining 🟡 is PLAT-6's distribution work, which is a
set of trust/distribution decisions rather than engineering left undone.

**This section is now RESIDUALS ONLY.** What each ticket did, and the D-number that did it, is in the Done
ledger below and in `git log`; repeating it here made 350 lines that went stale the moment a follow-up
landed. What is *not* recoverable from either — and is the honest boundary of what the MVP claims — is what
each ticket deliberately did **not** close. That is what is kept.

**Do not re-propose anything here.** The next work is Lane F · Console, starting at `CONSOLE-1`.

### Lane A · XDR

- **XDR-2 · Cross-domain alert normalization** — ✅ D213, D241. *Residual:* a detection that never reaches a
  decision is not projected; the domain label is a coarse grouping hint (ZT denials land under `nips`, and
  giving ZT its own domain needs the Event to distinguish access from egress — a contract change
  deliberately not made for a label).
- **XDR-4 · Cross-domain correlation rules** — ✅ D242; **the technique-vocabulary residual is closed
  (XDR-4b, D455)**: the `Decision` contract change was made, so a rule can name an ordered ATT&CK
  sequence (`T1552 → T1567.002`) alongside the domain sequence. The ids are DERIVED from signals and
  refused by the contract if outside the closed vocabulary — a policy cannot declare one. **The
  sequence rules now RUN ON THE CLOCK (XDR-4c, D456)**: before it, `Sequence`/`TechniqueSequence` were
  set in exactly one place in the tree outside tests — the `GET /incidents` query parser — so a
  narrative could be asked about and never reported. Named hunts come from a validated file, run on
  every correlation tick beside the breadth rule, and page with the hunt named; incidents are now keyed
  by (entity, rule) so two narratives on one asset cannot collide into one silently-updated row.
  *Residual:*
  two steps cannot be satisfied by one alert (deliberate — a moment cannot evidence "then"), so a
  chain that genuinely happens within a single event is not expressible as a sequence; no technique
  weighting in severity; no backfill of alerts that predate the column; no alert-storm suppression
  (see `CONSOLE-41`); no retro-correlation outside the window.
- **XDR-5 · Incident timeline** — ✅ D243. *Residual:* no backfill for pre-existing alerts/incidents; the
  timeline reports ledger COORDINATES and does not verify the chain (the anchor binary owns that); no
  timeline for `ueba_burst` incidents (explicit 409, never an empty list); `unified_alerts` retention must
  eventually cascade to the join.
- **XDR-6 · Coordinated cross-domain response** — ✅ D254. *Residual:* a policy that does not read
  `response_intent` is unaffected (data-not-command); the exec gate still fails open; an entity that never
  crosses the gateway is not blocked by it.
- **XDR-7 · Entity risk aggregation** — ✅ D255. *Residual:* a heuristic, not a calibrated probability;
  stepwise on the correlation interval; sticky (no decay until a later ticket).

### Lane B · SOAR (ADR-12)

- **SOAR-2 · Scheduled correlation + escalation** — ✅ D250. *Residual:* no escalation timers (SOAR-9
  shipped routing, not schedules); no reopen; no backfill outside the window.
- **SOAR-3 · Generic four-eyes approval object** — ✅ D251. *Residual:* no approval POLICY and no N-of-M —
  the caller decides.
- **SOAR-4 · Playbook engine v1** — ✅ D256. *Residual:* **no actuation** (Tier-1 by construction; SOAR-7/8
  own that); no DAG, no retries/backoff, no rate limit on playbook starts; `enrich` is local context
  assembly, not threat intel; **the approval gate is a one-operator human-in-the-loop gate, NOT two-human
  four-eyes, because the requester is the playbook.**
- **SOAR-5 · Enrichment + threat-intel** — ✅ D257. *Residual:* no EPSS/KEV (both key off a CVE id and
  nothing in the pipeline produces one); no geo/ASN (a licensed data file — a distribution decision); no
  STIX (a large untrusted-JSON surface; an external converter is the right shape); no IOC ageing,
  confidence or TLP; no retro-hunt when a feed lands; unsigned feeds still load when no key is configured
  (warned, not silent); **a hit ANNOTATES, never enforces.**
- **SOAR-6 · MTTA/MTTR** — ✅ D258. *Residual:* **no per-analyst aggregation** — deliberate, that is
  workforce surveillance, and a test asserts no series names an operator; no SLA targets or breach alerting
  (`CONSOLE-36`); no per-severity/domain split; contained-but-open is not counted as resolved.
- **SOAR-7 · Response-Intent seam (Tier-2)** — ✅ D252. *Residual:* a consumer that ignores intents is
  unaffected by design; **signing proves origin, not authority.**
- **SOAR-8 · Integration runners v1 (Tier-3)** — ✅ D260 (b), D261 (a). *Residual:* no vendor API shapes; no
  retries (an automatic retry of an irreversible call is how one failure becomes several); no rollback of a
  partially-applied multi-action verb; the subject crosses as the PSEUDONYM and the deployer's receiver must
  do the pseudonym→account join. ITSM sync is **polling, not a webhook** (sync-back lags one interval); only
  `closed` is synced (mapping intermediate states would corrupt SOAR-6's metrics); **forward-only survives,
  so a reopened ticket does NOT reopen its incident**; no comment/worklog sync.
- **SOAR-9 · Notification routing** — ✅ D259. *Residual:* **no templating** — an injection surface into
  whatever renders it; formatting belongs in the receiver. No escalation ladders, on-call schedules or
  rotations; no per-sink rate limiting or digesting; **routing matches kind and severity ONLY, never a
  subject** — which would be a re-identification surface and a way to route one person's alerts out of sight.

### Lane C · Zero Trust

- **ZT-4 · ZTNA client/connector model** — ✅ D249, extended by D427 (TCP CONNECT) and D428 (endpoint
  bypass fencing). *Residual:* the NETWORK half — the protected network accepting only the gateway — lives
  outside the product; no SOCKS; no split DNS.

### Lane D · Platform

- **PLAT-2 · Durable ingest by default** (ADR-2) — ✅ D245. *Residual:* not loss-free (unspooled-unpublished
  is gone; the stream's bounds still drop on a long outage); at-least-once, not exactly-once; non-telemetry
  subjects stay core-NATS best-effort by design. **BREAKING:** a JetStream-less broker must enable it or opt
  out.
- **PLAT-5 · Config management beyond env vars** — ✅ D262, D263; all binaries declare their configuration
  (D272/D273/D274) behind a whole-tree guard. *Residual, and larger than this entry used to admit:* **both
  the gateway AND the endpoint agent are all-bootstrap**, so PLAT-5b's dynamic, cluster-wide configuration
  reached only the server — a policy change on a hundred endpoints needs shell access on a hundred hosts.
  Ticketed as `PLAT-5c`/`-5d`/`-5e`. No staged rollout; no keystore. **BREAKING:** a dynamic field set in
  the environment no longer takes effect — it is reported, not silent (`OPENSHIELD_BREAKGLASS` is the
  deliberate, reported override).
- **PLAT-6 · Release, packaging & deploy** — 🟡 D264, D276 (signed SBOM), D277 (tag-triggered release that
  proves reproducibility before publishing). *Remaining:* Sigstore/cosign + transparency log, `.deb`/`.rpm`,
  macOS notarization — each a separate trust-or-distribution decision. **goreleaser and Helm are REFUSED,
  not deferred (D276); do not re-propose them.** *Residual for the console:* the SBOM is derived from
  `debug/buildinfo`, so it would describe zero npm packages — `CONSOLE-15`.
- **PLAT-9 · Operational lifecycle & recovery** — ✅ D265–D270, D275, D277, D278. *Residuals:* the control
  plane **cannot CONFIRM a fleet is disabled** — publication is best-effort and an agent offline past the
  TTL never applies it; D270 made each agent's actual enforcement state answerable, with the honest limit
  that **silence is not compliance**. Migrations are **FORWARD-ONLY**: rolling the binary back is supported,
  rolling the schema back is not (a skew is reported loudly and still STARTS, because refusing would turn a
  rollback into an outage). `restore-verify` verifies but does not back up or restore, and anchor cadence
  bounds what completeness can prove — **"I cannot tell" is a FAILURE**, because a truncated ledger hashes
  perfectly and only an anchor detects it. The kill switch's fleet path reaches only components that read
  the config store — **endpoint agents do not**, which is what `PLAT-5c` closes. No throughput figures are
  published because no load exercise has been run.

### Lane E · Endpoint

- **HIPS-3 inc 2a · Exec-gate IPC bridge** — ✅ D244 (VM-proven, kernel 6.8). *Residual:* the gate fails
  open by design, so a verdict that misses its deadline allows.
- **HIPS-3 inc 2b · Intent-driven inline `DENY_EXEC`** — ✅ D253 (VM-proven). *Residual:* a policy that does
  not read `response_intent` is unaffected (data-not-command); the gate still fails open, so containment
  depends on a live engine.
- **DLP-2a · Clipboard exfil producer** — ✅ D246, mediation D247 (VM-proven on X11). *Residual:* **Wayland
  stays observe-only** — its protocol cannot identify a paste's destination.
- **DLP-2b · Print exfil producer** — ✅ D248 (real-spooler proven). *Residual:* chain placement determines
  detection quality (text vs raster); only the head of a huge job is classified; no CUPS-bypassing paths; no
  watermark/redact; install is a root step.

---

## 🔧 Lane D (continued) · Platform — OPEN

Three tickets that are **not** part of the completed queue above. `PLAT-5c` gates `TOPO-4` and is what makes
`CONSOLE-21`'s configuration UI able to change anything on an endpoint or gateway rather than only display
it.

- **PLAT-5c · Configuration DELIVERY to endpoints and gateways — PLAT-5b is half-finished** — new work · L.
  *Owner correction, 2026-07-31: "configurations SHOULD be delivered to the node, we can't assume we need
  direct access to endpoints."* Correct, and the tree agrees more than the earlier plan admitted.
  **Endpoint agent config has ZERO dynamic fields. So does the gateway.** Every setting on both is
  bootstrap. Only the server got PLAT-5b's dynamic, cluster-wide scope (45 fields), and
  `internal/intent/fleetcontrol.go:22` states the consequence in its own words: *"D265's kill switch reaches
  server-side components through the configuration store. **ENDPOINT AGENTS DO NOT READ IT**"* — which is
  why the endpoint half of the kill switch had to be built as a separate signed channel in the first place.
  **This is a platform gap that predates the console; the console is only what makes it visible.**
  **The pattern is proven five times over** — fleet-control, signed risk/posture, signed IOC feeds, signed
  DLP indexes and response intents are all signed one-way channels to endpoints. Configuration is the one
  thing that does not use one. So this is the sixth instance of an established shape, not new architecture:
  signature, monotonic sequence, mandatory expiry, fail-toward-the-safe-state, with `fleetcontrol.go` as the
  reference implementation.
  **The first version of this ticket claimed typed `Field`s made it "a closed vocabulary by construction".
  That was WRONG, adversarial review proved it against the code, and ADR-15 in this same file already said
  so** — *"a configuration language is not a closed vocabulary in the INV-1 sense"* (line ~1469). The
  vocabulary is closed over **keys**, not **values**, and several declared keys are dereferenced by the
  consumer into things that execute:
  - `OPENSHIELD_WORKER_BIN` (`endpoint2.go:23`, `KindPath`) is **executed** as the sandboxed worker.
    `KindPath` validation is `os.Stat` — "the file exists".
  - `OPENSHIELD_EXEC_IPC_SOCKET` / `OPENSHIELD_OPEN_IPC_SOCKET` (`endpoint.go:41`, `endpoint2.go:101`) name
    the socket the **privileged, `CAP_SYS_ADMIN`, fanotify-answering agent** asks for exec and open
    verdicts on. Repoint them and any local user answers ALLOW for every exec — **a direct INV-2 breach**.
  - `OPENSHIELD_CONTROL_PLANE_KEY` (`endpoint2.go:35`) is the key that verifies fleet-control *and* would
    verify this channel. Delivering a new path **re-roots trust permanently — a TTL does not undo a key
    swap.**
  - `OPENSHIELD_ENFORCE` (`endpoint2.go:41`, `gateway.go:48`) is a declared field meaning "set = enforce".
    Delivering it **empty** stops enforcement fleet-wide with no four-eyes, no sequence, no TTL — and
    because it is not the kill switch, `KillSwitch.Engaged()` stays false and the console's
    "N enforcement suppressed" counter reads **zero**. INV-5's claim that enforcement is reachable exactly
    two ways becomes false the day this ships.
  **So the design is three controls, and the first two are categorical:**
  1. **`Deliverable bool` on `Field`, default FALSE**, granted per field by explicit declaration and
     **structurally denied** for any field dereferenced into an executable, a socket, an IPC peer, a key, a
     CA, a roster or a URL. Enforced **in the endpoint's applier**, so a validly signed message carrying an
     undeliverable key is still refused. Guarded by a whole-tree test in the D274 shape: walk every
     `Deliverable` field and fail if its value reaches `exec.Command`, `net.Dial`, or a key/CA load.
  2. **Security-relevant transitions cannot ride this channel at all.** `OPENSHIELD_ENFORCE`,
     `OPENSHIELD_USB_ENFORCE`, `OPENSHIELD_ATTEST`, `OPENSHIELD_OPERATOR_ROLES_STRICT` are protection
     switches; an on→off transition **is** `ENFORCEMENT_DISABLE` and may only travel the fleet-control
     channel, which already has the four-eyes, the sequence and the mandatory TTL.
  3. **The coverage check moves to the CONSUMER** — see `PLAT-5d`, which is the load-bearing one.
  `Accept`: a dynamic endpoint setting changes on a live agent with no shell access; an undeclared key is
  refused; **and a signed set containing `OPENSHIELD_WORKER_BIN` or `OPENSHIELD_ENFORCE=""` is refused by
  the agent**. Mutations: mark a dereferenced field `Deliverable` → the whole-tree guard must fail; accept a
  security-relevant off-transition → the refusal test must fail.
- **PLAT-5d · The coverage check belongs on the ENDPOINT, not in the console** — PLAT-5c · L. **The
  structural finding, and it invalidates how ADR-15 was specified.** The coverage meter recomputes in the
  canvas and the `ENFORCEMENT_DISABLE` routing is decided by the `TOPO-3` compiler — **both in the control
  plane. INV-1's threat model is a COMPROMISED control plane.** An attacker who owns it does not run the
  compiler; they publish a signed change set directly. Everything fleet-control gets right, it gets right
  **on the endpoint** (`fleetcontrol.go:79-133`: signature, sequence and expiry all checked in `apply`),
  which is precisely why it survives control-plane compromise. ADR-15's coverage rule is currently the only
  safety property in the design living on the wrong side of that boundary — `TOPO-2b`'s live meter is a
  good **UX** property and was wrongly promoted to an invariant.
  So: each endpoint and gateway computes its **own local protection level** from the fields it holds
  (enforcers registered, monitored dirs non-empty, gate socket reachable, feed verified) and **refuses any
  delivered set that lowers it** without an accompanying `ENFORCEMENT_DISABLE` authorization, auto-reverting
  at that authorization's TTL. `Accept`: mutate the applier to accept a lowering set without the
  authorization → the test must fail.
- **PLAT-5e · Fail-safe resolution, atomicity and honest acknowledgement** — PLAT-5c · M. Four delivery
  defects that are each independently sufficient to make the feature unsafe.
  **(a) Fail-safe is INVERTED for endpoints.** Fleet-control fails safe because absence means enforcing.
  Config has no safe absence: `Resolver.raw` resolves a dynamic field with no value to `f.Default`, and
  `endpoint2.go:15` says *"almost every detection source is OFF by default"*. So an agent that is
  partitioned, expired, or never received a set resolves to **no FIM, no canaries, no memory scanning, no
  clipboard DLP, no exec monitoring** — an attacker who can partition an endpoint disarms it, and the
  design would call that "failing safe". Fix: resolution is **delivered → last-good delivered → the host's
  BOOTSTRAP value**, never the declared default; TTL expiry is a per-field revert timer to that fail-safe;
  and a stale set makes the agent report **degraded**, rendered in the canvas state rail.
  **(b) Change sets are not atomic across a host.** An endpoint is three processes (privileged agent,
  engine, worker) with different field sets, and `Snapshot` swaps atomically only *within* one process. A
  set touching `OPEN_GATE_DIRS` (agent) and `OPEN_IPC_SOCKET` (engine) applies at different moments, and the
  intermediate state is "gate enabled, pointing at the wrong socket" — documented as fail-open. Fix: the
  change set is the unit of atomicity across the host — stage, then commit on a barrier all three consumers
  acknowledge, or refuse the set.
  **(c) Silent no-ops.** Endpoint settings are read once at startup (`cmd/openshield-engine/main.go:1017`
  registers enforcers from `os.Getenv` at boot). Flipping a field to dynamic does not make its consumer
  re-read it, so the console would show the new value while the host runs the old one — the exact
  console/host disagreement PLAT-5b exists to prevent. Fix: a per-field `HotAppliable` flag proven by a test
  that the reader re-reads per tick; a non-hot-appliable field is delivered as **"pending restart"**, never
  applied silently.
  **(d) Acknowledgement must not be ordinary telemetry.** INV-4 says unsigned telemetry is never evidence,
  yet a staged rollout is a control decision driven by it: forged positive acks show `51/51 applied` while
  the fleet runs the old config *and* advance the rollout. Fix: the ack is **signed by the enrolled agent
  key and carries the hash of the effective values**, not a revision number — and the UI renders
  **"acked" and "verified in effect" as different states**, because an ack proves receipt, never effect.

---

## 🚧 Lane F · Console (PLAT-1) — the next queue

**Design lives in the specs, not here.** `docs/superpowers/specs/`: `2026-07-31-console-plat1-design.md`
(architecture, auth, ADRs), `2026-07-31-console-ux-spec.md` (pages, states, workflows, settings IA,
permission matrix), `console-mockup.html` (visual reference). Entries below are the queue: what, why in one
or two sentences, what it depends on, and what closes it. **Read the spec before starting a ticket.**

**Start at `CONSOLE-1`, and read this first.** `requireTier` (`internal/controlplane/views.go:131`)
authenticates by client certificate **or** OIDC bearer and then discards `auth.identity` — it never reaches
the request context. Eight handlers re-derive identity from `operatorIdentity(r.TLS)` (`views.go:166`),
which returns `""` without a peer certificate. **So a ZT-7 SSO operator today passes the tier gate and is
then refused by `/alerts/ack`, `/incidents/ack`, `/incidents/transition`, `/incidents/timeline`,
`/cases/*`, `/searches/save`, `/subject` and `/view`.** D373 shipped an authentication method that reaches
almost none of the product. Same shape as D415/D417/D418.

And the obvious fix is a trap: a certificate mints `"operator:" + CN`, a token mints the raw `sub`, and
four-eyes is `AND requester <> $2` (`internal/controlplane/approvals.go:119`). Thread the bearer identity
through unchanged and **one human requests from the CLI and approves from the browser** — two-person
control collapses on case closure, `CONTAIN` and fleet `ENFORCEMENT_DISABLE`. `CONSOLE-1` fixes both or
neither.

### Lane F index

| ID | Ticket | Phase | Depends | Size |
|---|---|---|---|---|
| CONSOLE-1 | Canonical operator principal | 0 | — | L |
| CONSOLE-2 | Toolchain, dependency budget, reproducible bundle | 0 | — | M |
| CONSOLE-3 | Browser session auth | 0 | 1 | L |
| CONSOLE-4 | Incidents queue + timeline detail *(slice 1)* | 1 | 1, 3 | L |
| CONSOLE-5 | View-audit repair + `investigation_views` retention ✅ | 2 | 1 | M |
| CONSOLE-6 | Keyset pagination ✅ *(+6b: `/alerts`, `/search`, `/incidents`)* | 2 | — | M |
| CONSOLE-7 | Operator-tier `/health` | 2 | — | S |
| CONSOLE-8 | Fleet inventory + break-glass surface 🟡 | 2 | 7 | M |
| CONSOLE-9 | Entity surface over HTTP ✅ | 2 | — | M |
| CONSOLE-10 | Replay + explain over HTTP ⛔ | 2 | **PLAT-5c**, CONSOLE-40 decision | M |
| CONSOLE-11 | Untrusted-render component + approval hardening | 2 | 3 | M |
| CONSOLE-25 | Step-up re-authentication | 2 | 3, 11 | S |
| CONSOLE-29 | Session inventory + revoke | 2 | 3 | S |
| CONSOLE-40 | Stable `rule_id` on alerts | 2 | — | S |
| CONSOLE-41 | Tuning: disposition → exception *(absorbs CONSOLE-27)* | 2 | 4, 40 | L |
| CONSOLE-42 | Detector health + exception register | 2 | 41 | M |
| CONSOLE-43 | Quiet start *(paging only)* | 2 | 41 | M |
| CONSOLE-26 | Worklist: assignment + bulk | 2 | 4 | M |
| CONSOLE-28 | Export from every grid | 2 | 5, 6 | S |
| CONSOLE-12 | Hunt, Fleet, Explain + pivot spine | 2 | 6, 8, 9, 10, 11 | L |
| CONSOLE-14 | Assurance gates *(exit criteria)* | 2 | 12 | M |
| CONSOLE-15 | Console in the signed release *(exit criteria)* | 2 | 2 | M |
| — | *Phase 3 groups: surfaces · detection admin · Zero Trust · enterprise · i18n* | 3 | | |

**Retired IDs, recorded so they are never reused:** `CONSOLE-23` (policy & compliance packs) merged into
`CONSOLE-49`; `CONSOLE-27` (suppression + disposition) merged into `CONSOLE-41`, which was the same ticket
written in a later round — the disposition schema half moved to `CONSOLE-4`, where it is XS rather than a
backfill.

**Phase 2 is 19 tickets and that is still not an MVP.** It is honest to say so rather than relabel it: the
five-verb core (`-4`, `-12`, and the read models behind them) plus the security work the console's own
threat model forces (`-5`, `-11`, `-25`, `-29`) plus tuning, without which the queue stops being read
(`-40`…`-43`). If it must shrink further, `-26`/`-28`/`-43` are the candidates, and the cost of each is
stated in its entry.

### Phase 0 · Foundation

- **CONSOLE-1 · One canonical operator principal** — ✅ **COMPLETE (D468, D469, D470, D471).** Archived
  `2026-08-04-console-1-operator-principal`, specs synced. Two deviations are recorded in its task list
  rather than taken silently: the route set is a closure GUARD instead of a shared `[]route` table (37/37,
  no divergence), and the scope predicate was NOT built — the principal is already on the request
  context, so a field that always says "all" is unwired code by construction, and the requirement that
  survives moved to `CONSOLE-6`. Namespaced principals (`cert:<CN>` / `oidc:<issuer>#<sub>` / `svc:<name>` /
  `playbook:<name>`) threaded through `requireTier` onto the request context; the eight
  `operatorIdentity(r.TLS)` sites read from there; `operator_identities` links principals to one account
  and **four-eyes compares the account, not the string**; the issuer is part of an SSO identity, so a
  provider subject cannot inherit a certificate CN's row; and **only a human may GRANT an approval** —
  enforcing what the capability spec has claimed since SOAR-4 with nothing behind it, before `svc:`
  principals made it reachable. Automation may still request one; that is the whole purpose of a
  wait-for-approval step.

  **D470 split the admin tier's two authorities apart.** `admin` meant "can change configuration" AND
  "can read everything held about a named human" — the DSAR export (which sat at the ANALYST tier, so the
  broadest read role could compile a dossier on anyone), the legal-hold release, and the record of who
  looked. `privacy-officer` is now a SECOND AXIS rather than a fourth rank: no tier satisfies it,
  including admin, and it grants no tier. Ranking it could not express the control — above admin it
  inherits configuration, below it the admin inherits the dossier. **The admin administers the system;
  the privacy officer oversees the admin.** Migration 049 grants every existing admin BOTH and says so
  with a count, so nothing breaks on upgrade and **the separation is available but not in force** until
  someone decides who the privacy officer is; `operator-role set <id> admin` replaces the grant and
  narrows them. Along the way `/views` was wired: `Views`/`ViewsBy` had no caller anywhere, so every view
  recorded since D20 went into a table nothing could read — the reader half of `CONSOLE-5`, arriving
  early because the split needed something for the privacy officer to oversee.

  **D471 gave the machine principal a credential.** `svc:<name>` parsed, was grantable and was refused
  four-eyes — and nothing could present one, so every `svc:` grant authorized a caller that could not
  exist and every automation calling the operator API ran on a PERSON's certificate or SSO token. That is
  the exact input the four-eyes account comparison exists to reject. `machine-credential
  issue|rotate|revoke|list` mints an `osm_`-prefixed bearer secret (SHA-256 stored, plaintext printed
  once), **expiry mandatory, 90-day ceiling, checked at authentication**, rotation with no overlap window,
  and issuance granting nothing. **The D375 wiring defect was caught before shipping:** the
  certificate-less handshake relaxation was gated on operator SSO, so a machine credential on a
  deployment with no identity provider would have died at the handshake with `tls: certificate required`
  — mutation-verified against the real binaries. `OPENSHIELD_OPERATOR_MACHINE_TOKENS=1`, off by default,
  with a boot warning when live credentials cannot reach the listener (D31).
  **⚠️ UPGRADE BREAK: every operator must be re-granted.** Grants were stored under a BARE identity
  (`certIdentity` returned the CommonName unprefixed for the ROLE lookup while `operatorIdentity`
  returned `operator:<CN>` for the AUDIT trail — one person, two strings, one process; SCIM stored the
  raw `userName` in the same column). **That shared column IS the collision** the ticket describes, and a
  bare row does not record which credential class it was for — so renamespacing means guessing, and
  either guess grants access to the wrong credential. Legacy rows are left denying, kept visible, and the
  migration RAISEs a notice with the count.
  **Still open:** the machine principal's own lifecycle (issue/scope/expire/rotate/revoke, expiry
  mandatory); the scope predicate in the pagination cursor; and **`admin` split into `admin` +
  `privacy-officer`**, because one tier currently fuses "can change configuration" to "can read every
  subject's personal data".
  **Two roadmap claims here were STALE and are corrected:** `/report/response` IS mounted
  (`enroll_http.go:124`), and the route set is closed — a guard now fails when a registered route is
  unmounted or a mounted one unregistered, in place of the proposed shared table, because restructuring
  37 security-gated mounts risks landing one at the wrong TIER. *OpenSpec:
  `2026-07-31-console-1-operator-principal`.*
- **CONSOLE-2 · Toolchain, dependency budget, reproducible bundle** (ADR-13) — new work · M. React/TS/Vite
  under `apps/console/`, embedded via `embed.FS`, same origin, no CDN, Node-free `go build`. Budget is a
  **number** in CI; each direct dependency gets the one-sentence justification D276 demanded when it refused
  goreleaser. Logical CSS properties and the no-bare-string lint land here — the only i18n work that cannot
  be retrofitted. `Accept`: pinned-digest **network-less** container build, `SOURCE_DATE_EPOCH`, and a
  byte-identical rebuild check that **fails the release** — `internal/release/release_test.go:161` already
  tests Go reproducibility and embedding bundler output puts a non-deterministic input inside that digest.
  Note `--ignore-scripts` is not the control: `vite.config.ts` and its plugin import closure execute with
  filesystem and network access during the build, on the machine holding the signing key.
- **CONSOLE-3 · Browser session auth** (ADR-14) — CONSOLE-1 · L. OIDC Authorization Code + PKCE, `state`
  bound to a pre-auth cookie, `nonce`, callback `iss` check; server-side session in a `__Host-` cookie
  (`HttpOnly`, `Secure`, `SameSite=Strict`, idle + absolute timeout); CSRF as an `X-OpenShield-CSRF`
  **header** so no existing route signature changes, plus an independent `Origin` check. The console's OAuth
  client is **separate from the bearer verifier**, and a token whose `aud` is the console `client_id` is
  refused on the bearer path. **`REQUIRE_DPOP=1` refuses console login and says so at startup** — a cookie
  has no proof-of-possession and silently exempting the browser is the downgrade that switch prevents.
  `Accept`: authorization unchanged; mutation — make the session carry a `groups` claim → the test fails.

### Phase 1 · Slice 1 — one page, end to end

- **CONSOLE-4 · Incidents queue + timeline detail** — CONSOLE-1,3 · L. The riskiest unknowns proved on the
  real path before any framework generalization: session auth → `/incidents` → `/incidents/timeline` with
  the **three evidence states rendered visually distinct** (resolved / unresolved / derived) → the view
  recorded under the session principal. No i18n, no palette, no a11y gates yet. Closure **disposition**
  (true positive / false positive / benign-authorized / duplicate) lands in the schema here: XS now, a
  backfill across an attributed forward-only lifecycle later. `Accept`: an analyst reads a cross-domain
  timeline and a derived evidence link is not mistakable for a resolved one.

### Phase 2 · The MVP console

*Read models first, then the security primitives the console's own threat model forces, then tuning, then
the surfaces, then the two exit-criteria tickets.*

- **CONSOLE-5 · View-audit repair + `investigation_views` retention** — ✅ **SHIPPED (D482).** The reader
  landed with D470; the RECORDING half and retention land here. Recording moved from eight-more-handlers
  to ONE wrapper around the operator read mux that records **by default** — `/alerts`, `/search`,
  `/events`, `/logs`, `/searches/run`, `/incidents`, `/incidents/recurrences` and `/entities` are now
  audited, and *not* recording is what costs somebody a named exemption with its residual
  (`viewAuditExempt`). The record carries the ROUTE and the canonicalised, bounded FILTER, so a dashboard
  refresh is distinguishable from a search for one named endpoint. `OPENSHIELD_VIEW_AUDIT_RETENTION`
  (8760h, longer than the fleet window) purges the table on the leader's retention loop and records the
  compliance event; the subject's DSAR now counts the views that named them, and `/views?viewer=` is the
  operator's own access path. *Residual, stated:* `/fleet`, `/overdue` and the `/config` reads stay
  unaudited — the first two are a target list of dark endpoints, the third is "which detections are
  disabled" — and a read implemented as `POST` would escape the wrapper (there is none today). Archived
  `2026-08-06-console-5-view-audit`, specs synced.
  **HARDENED (D483)** after two independent reviews of the shipped commit found the control defeatable and
  unfalsifiable in six places: `OPENSHIELD_VIEW_AUDIT_RETENTION` had **no floor**, so an administrator —
  the party the table records — could set `0s` with a one-minute interval and erase the whole
  accountability record through the product's own sanctioned delete path, filing a compliance event
  saying it was policy (`OPENSHIELD_FLEET_RETENTION` had the same hole at exactly zero, found while
  fixing this one); the five in-handler recorders wrote `route=''`, which migration `053` declares means
  *recorded before CONSOLE-5*, so the five highest-sensitivity reads were indistinguishable from legacy
  rows; the fail-closed branch **discarded its error**, and `/health` — exempt from recording — reported
  healthy while every other operator route answered 500; **nothing verified** that the in-handler routes
  still record (delete the call from `dsarHandler` and the DSAR is unaudited with the suite green) or
  that a new mount passes `opRead`, which is what `CONSOLE-28` walks into; and `subject_filter`, the
  DSAR's join column, had no index on the table this change makes the largest. Also: the retention tick's
  three purges were coupled so a fleet failure skipped the other two; `/searches/run` recorded a mutable
  name instead of the filter; the 512-byte bound was asserted only against itself; and the DSAR counted
  its own access with no breakdown. Archived `2026-08-06-console-5-view-audit-hardening`.
  Was: `RecordView` had four call sites (`views.go:47`,
  `timeline.go:197`, `dsar.go:127`, `cases_http.go:126`) while `docs/threat-model.md` bounded the
  malicious-operator insider with "who LOOKED is recorded" — a UI turns that into "scroll the fleet and
  leave nothing" — and migration `007_investigation_views.sql` had no TTL, no purge and no DSAR path while
  storing raw non-pseudonymised operator identities.
- **CONSOLE-6 · Keyset pagination** — ✅ **SHIPPED (D481).** `GET /events` returns rows + `has_more` + `next_cursor`; the walk resumes at `(received_at, id) < (…)`. The cursor carries a POSITION ONLY and authority is re-derived per page, so the CONSOLE-1 inherited requirement holds by construction. Was: `maxSearchLimit = 1000` (`operator_read.go:281`), no
  cursor, no `has_more`. Hunt cannot be built on "top 1000 rows, no row 1001" against 90-day retention; the
  existing `ORDER BY received_at DESC, id DESC` is already a usable cursor.
  **⚠️ REQUIREMENT INHERITED FROM CONSOLE-1: A CURSOR MUST NEVER BE A BEARER OF AUTHORIZATION.** Resolve
  the caller's authority from their principal on every page — a cursor that encodes a position and is
  honoured without re-deriving it lets one operator replay another's cursor and page through rows they
  were never entitled to. Nearly free to prevent while the cursor is being designed; expensive once
  clients hold cursors. CONSOLE-1 deliberately did NOT build an inert scope field for this — the
  principal is already on the request context, so any scope is derivable there when tenancy is designed,
  and a constant that always says "all" is unwired code by construction (see the CONSOLE-1 tasks
  deviation). *Residual:* no stable snapshot across pages while ingest is live.
  **CONSOLE-6b — `/alerts`, `/search`, `/incidents`** — ✅ **SHIPPED (D484).** All three return
  `{rows, has_more, next_cursor?}`; the walks resume at `(detected_at, id) < (…)` and
  `(last_seen, id) < (…)`. **D481's "mechanical now the shape is settled" was right about the shape and
  wrong about the work, and this entry corrects it.** The mechanism did port in about forty lines per
  surface with no migration — both tables already had `id BIGSERIAL PRIMARY KEY`, so the feared missing
  tiebreaker never existed. But three questions `/events` never had to answer had to be decided: the
  version tag had to become a **namespace** (`a1`/`i1`), because otherwise an `/alerts` cursor decodes
  cleanly on `/incidents` and serves a wrong-but-plausible page — the D481 failure moved from row-count to
  row-identity; a **tie fixture** was needed, because a walk over distinct timestamps passes against a
  boundary that ignores the row id; and `/incidents` **is not append-only**, so an unvisited open incident
  can be bumped ahead of the walk and be absent from the rest of it. A future "just extend it to the next
  surface" should budget for the same three questions rather than for a copy.
  **Two reviews of the working tree then found a fourth question none of the three anticipated: what the
  new parameter does to everything that STORES a query.** A saved search could capture a `cursor=` and
  freeze itself forever — on the alerts surface this change touched AND on the events surface D481 shipped
  — so the hunt goes on returning rows while permanently excluding everything newer, which is the failure
  saved searches exist to prevent. Refused at save and at run. The reviews also found `/incidents`
  answering two envelope shapes from one route (`?rule=cross_domain` served a bare array, so a console
  decoding `rows` renders empty while incidents exist) and answering **200 and page 1** to a cursor on a
  route whose other branch 400s; a read that WROTE before validating its parameters, so a request that
  then 400'd had already correlated and possibly paged the SOC; the one new requirement with no test; a
  now-unreachable `RecentPeerAlerts` carrying the exact untiebroken `ORDER BY` this change argued against;
  and two false comments about `last_seen` whose correction makes the accepted residual NARROWER than the
  design claimed (the upsert writes `max(detected_at)`, not `now()`, so re-materializing with no new
  alerts moves nothing). All fixed in D484.
  *Residuals:* open incidents mutating mid-walk (bounded to `state='open'` AND to live detection rather
  than walk depth, pinned by two tests, no snapshot built); **`/searches/run` still returns bare capped
  arrays with no `has_more`** while the live endpoints return pages — blocked on `/logs` having no page
  function, since paging two of three surfaces would make `results` mean a different shape per surface;
  `peer_alerts` still has no index on `detected_at` — a deep walk is a sort over a full scan either way,
  and an index is a follow-up rather than something quietly matched here.
  *Found by the same reviews, NOT caused by this change and deliberately not fixed in it:*
  `TestScheduledCorrelationRaisesAndPagesWithNoOperatorRequest` (`soar2_test.go`) failed once in four
  runs. `CorrelationFailures` (`soar2.go`) is a package global that no test resets, and
  `hunt_collision_test.go` leaks a `RunCorrelationLoop` goroutine whose next tick lands after
  `t.Cleanup(pool.Close)` and increments it. CONSOLE-6b touches neither, but its new schema-dropping
  tests shift the timing window, so **expect intermittent CI red** until a follow-up resets the counter
  per test and joins that loop. Recorded as a decision rather than a silence.
  ✅ **FIXED in D485** — the loop is JOINED, not reset: the follow-up's own note about resetting the
  counter was wrong, because a reset would have hidden the next leak instead of fixing this one.
- **Two flaky counter tests (no ticket)** — ✅ **FIXED (D485).** Both were counters read across a
  goroutine boundary, neither a product defect, and a flaky CI is how a team learns to ignore red.
  `TestATicketDoesNotWorkFromAnotherDevice` (`internal/gateway/socks_test.go`, red on `2a5b167`) read
  `SOCKSRefused()` after the client had the RFC 1929 refusal, and every refusal path in `handleSOCKS`
  answered first and counted second — the CONNECT tunnel beside it has always done the opposite. Fixed
  as a class: nine paths, plus the `0xFF` written inside `socksNegotiateMethod`, which now counts its
  own refusals because a caller cannot count before a write it does not perform.
  `TestScheduledCorrelationRaisesAndPagesWithNoOperatorRequest` is the entry above.
- **CONSOLE-7 · Operator-tier `/health`** — ✅ **SHIPPED (D472).** `GET /health` at analyst tier: leader
  held, broker connected, PLAT-10 ingest repairs, database reachable, PLAT-9 schema skew, last external
  anchor — each read at request time. **A REPORT, NOT A LIVENESS PROBE:** always 200, because a follower
  is healthy and one status code cannot say what is wrong. Each problem names its consequence;
  `degraded` is derived from the list so the two cannot disagree; an empty list serializes as `[]`.
  `SetLeaderHeld` is wired from the real election and proven so by the integration test against the
  shipped binary. Archived `2026-08-04-console-7-operator-health`, specs synced.
- **CONSOLE-8 · Fleet inventory + break-glass surface** — 🟡 **INCREMENT 1 SHIPPED (D473).** `GET /fleet`
  (roster: enrolment, revocation, last VERIFIED telemetry, silence, the agent's own enforcement report and
  applied sequence) and `GET /fleet/controls` (the break-glass register), both at analyst tier.
  `fleet_controls` records every published control between the four-eyes gate and the wire, fatally; the
  register joins `approvals` for the pair that authorized it; suppression is DERIVED from the
  highest-sequence unexpired control, never stored. Fixed a shipped defect on the way: `fleet-control
  publish` never applied the broker's TLS options, so the emergency disable was unpublishable on any
  mutually-authenticated deployment.
  **INCREMENT 2 SHIPPED (D474).** `openshield-engine` — the real endpoint agent — now publishes a signed
  heartbeat carrying its actual kill-switch state, applied fleet sequence, platform, version and spool
  depth; `handleSigned` projects the PLAT-9 acknowledgement (it had no producer at all); and
  `internal/buildinfo.Version` is stamped by `release.sh` into a symbol that exists.

  ### ⚠️ THE SIMULATOR HAD THE CAPABILITIES AND THE PRODUCT DID NOT

  `cmd/openshield-fleet-agent` says of itself that it *"does NOT classify files or run the pipeline (that
  is the engine)"*. It was nonetheless the **only** producer in the tree for five features. **All five are now
  fixed (D474–D477)**; the table stays because the detection signature is the reusable part:

  | Capability | Ticket | What is broken on a real deployment | Status |
  |---|---|---|---|
  | `PublishHeartbeat` | T-018/D16, PLAT-9 | idle endpoint ≡ dead endpoint; acknowledgement table empty | ✅ D474 |
  | version stamp | PLAT-6 | every shipped binary carries no version | ✅ D474 |
  | `SetSpool`/`queue.Open` | D40/D67/T-024 | a broker outage lost endpoint telemetry outright (fleet view, not evidence — the local ledger held) | ✅ D475 |
  | `posture.Publish` | D92/D85, HON-4 | the tamper-lockout denied every REAL endpoint and admitted only the simulation | ✅ D476 |
  | `binaryIntegrity` | PLAT-6 | answered only to a local log, on the host that may itself be compromised | ✅ D476 |
  | `attest` (TPM) | ZT-1/D190 | an attestation-requiring policy refused EVERY real endpoint — the verifier fails closed | ✅ D477 |

  **The detection signature is reusable and worth keeping:** diff what `cmd/openshield-fleet-agent` wires
  against what `cmd/openshield-engine` and `cmd/openshield-gateway` wire. PLAT-2 found durable ingest this
  way; D474 found three more. A capability demonstrated by the simulation is not a capability the product
  has.

  **What the platform still does not collect.** `agent_enforcement` (`heartbeat.go:72`) answers
  what agents SAY; the following are absent from the surface because they are absent from the product, and
  they were NOT shipped as empty fields:
  - **platform / version / spool depth** — `Heartbeat` has five fields and none is any of these;
    `agent_version` appears nowhere in the tree. Additive proto fields + agent wiring + a projection. This
    is the next increment and it is small.
  - **attestation verdict + TTL** — lives in the gateway's in-memory `AttestationVerifier`, in another
    process. Surfacing it needs a transport, not a query.
  - **posture** — the gateway's in-memory `PostureStore`, keyed by the **pseudonymous subject** (D23), not
    by `agent_id`. Joining it to the agent roster would re-identify the subject the pseudonym exists to
    protect. ⚠️ This is a privacy boundary to be argued, not a join to be written.
- **CONSOLE-9 · Entity surface over HTTP** — ✅ **SHIPPED (D480).** `GET /entities` serves the device⋈user
  graph joined to per-entity risk, or one entity via `?value=` from either of its names — the console pivot.
  `xdr.Store` had **no reader at all** (Resolve/LookupAny/Link each answer "what is the id for THIS name");
  it now has `Entities` and `EntityFor`. Risk is ABSENT where no alert concerns the entity, never zero; the
  page counts entities rather than join rows; a read never creates; an unknown value is 404. Analyst tier —
  the graph is pseudonym⋈pseudonym, and re-identification stays `/subject` (the privacy officer's).
- **CONSOLE-10 · Replay + explain over HTTP** — ⛔ **BLOCKED, and not on effort. Both halves are.**
  `openshieldctl replay` is CLI-only, and moving it to the control plane produces a route that answers a
  question nobody asked. The extraction it needs is done (D479): `cli.ReplayResultFor` returns the
  comparison structurally and the CLI is now a renderer over it, so whoever builds the surface cannot
  reimplement the comparison — an operator who gets "REPRODUCED" from the console and "DIVERGED" from the
  CLI has learned only that the product cannot be trusted about the one thing it claims to be good at.

  **⛔ THE REPLAY HALF IS BLOCKED ON `PLAT-5c`.** Replay needs two things and the control plane has
  neither for an endpoint:
  1. **The ledger.** `cmd/openshield-server/main.go:6` states it outright — the hash-chained record is
     *"the agent's local forward-secure ledger, NOT this aggregate."* Each endpoint writes to its own
     database. The control plane holds the PROJECTED decision in `fleet_telemetry` (`kind='decision'`),
     which is the same proto but not the tamper-evident record.
  2. **The policy.** `policy.SelectFromEnv` reads the *server's* `OPENSHIELD_POLICY_*`. Endpoints
     deliberately do not read the configuration store (`endpoint2.go`: making engine settings dynamic
     would invalidate the premise D269's signed fleet-control channel rests on), and delivering
     configuration to endpoints **is `PLAT-5c`, which is open.**

  So a control-plane `/replay` would re-evaluate under the SERVER's policy and compare against an
  ENDPOINT's decision. On any fleet whose endpoints are not configured identically to the server,
  **"DIVERGED" is the normal result** — a route that cries wolf until operators stop reading it. Worse
  than absent.

  The alternative is an ENDPOINT-side HTTP surface, which the engine does not have and which is a much
  larger decision than this ticket implies (a new listener on every endpoint is new attack surface). That
  is the owner's call, not this ticket's.

  **⛔ THE EXPLAIN HALF IS BLOCKED ON THE SAME `decision.proto` QUESTION AS `CONSOLE-40`** — and this is
  the second ticket that question caps. "Which pack and rule won under the most-restrictive-wins lattice"
  is not recoverable: `selectWinner` returns a `candidate` carrying `name`, and `policy.go:287` builds the
  `Decision` with `PolicyId: s.id` — the COMPOSITE's id. **`win.name` is discarded.** `Reason` carries
  `win.reason`, which is operator-authored free text and cannot be an identifier.
- **CONSOLE-11 · Untrusted-render component + approval hardening** — CONSOLE-3 · M. One `<Untrusted>`
  component is the **only** path telemetry reaches the DOM, with an href scheme allowlist applied inside it
  — "a pivot menu on every value" turns every telemetry string into a potential `href`, and
  `javascript:`/`data:` are blocked by no CSP directive. Tree-wide lint ban on `dangerouslySetInnerHTML`.
  The four-eyes screen renders a **server-generated closed-vocabulary summary** (verb, subject count, blast
  radius, TTL) above the requester's free text, and the approve POST carries a one-time token bound to
  `(approval_id, requester, digest of the summary shown)` so a stale or re-rendered row fails closed.
- **CONSOLE-25 · Step-up re-authentication for destructive acts** — CONSOLE-3,11 · S. The compensating
  control for the privilege escalation the console introduces — a stolen bearer token is effectively
  read-only today, a session is write-capable by definition, and a certificate is not phishable while a
  session is. Re-prove identity (`acr_values`/`max_age`, phishing-resistant) at `CONTAIN`,
  `ENFORCEMENT_DISABLE`, legal-hold release, DSAR export and case closure; **binds to the one-time token
  `CONSOLE-11` already issues.** Also the first place the product states that MFA is delegated to the IdP.
- **CONSOLE-29 · Session inventory, revoke-all, deprovision kills live sessions** — CONSOLE-3 · S.
  Per-request role resolution covers *authorization*, not session *existence*, and not "the analyst left and
  their laptop is unlocked". Enumerate, terminate one or all, and make SCIM deprovisioning and an
  `operator-role` revocation invalidate live cookie sessions. A query and a delete **now**; a security
  incident later.
- **CONSOLE-40 · Stable rule identity on alerts** — new work · **S→M, see the constraint below.**
  **Blocks every tuning ticket.** `unified_alerts` (migration 025) carries `domain` and `dedup_key` but no
  stable rule identifier, and `dedup_key`'s own comment calls its format "a projection detail" with a
  fallback. Adds `rule_id` written by every producer, with a whole-tree guard in the D274 shape so a new
  detector cannot ship without one.
  **⚠️ CONSTRAINT MEASURED 2026-08-04, and it is why this is not an S.** There are three producers
  (`decision_alerts.go`, `beaconing.go`, `recordDeviceUnifiedAlert`). Two are single-detector and their
  rule identity is a constant. The third is the pipeline, and **the Decision contract has no rule-level
  identity to carry**: `Decision.policy_id` is the STAGE id and `policy_version` its version, while the
  thing that actually fired is the winning *member* of the composed module set (`candidate.name` in
  `internal/policy/policy.go`) — which is discarded when the Decision is built. `reason` is
  operator-authored free text and cannot be an identifier. So CONSOLE-40 must choose:
  (a) add a rule/member field to `decision.proto` — the honest identity, but a change to a contract
  written into a hash-chained ledger; (b) accept STAGE-level granularity, which means an exception in
  CONSOLE-41 can only be scoped to "the endpoint policy" and not to a rule, defeating the point; or
  (c) derive one from `(domain, action, kind)`, which is the same "projection detail" criticism this
  ticket exists to fix. **(a) looks right and should be decided before the ticket starts**, since (b) and
  (c) silently cap what CONSOLE-41/-42/-43 can ever offer.
- **CONSOLE-41 · Tuning: disposition → exception, with a preview that cannot lie** — CONSOLE-4,40 · L.
  *(Absorbs the former CONSOLE-27, which was the same ticket written in an earlier round.)*
  **The surface that decides whether the console gets used**, not an admin convenience: if week three
  produces forty alerts a day and thirty are noise, analysts stop reading the queue regardless of detection
  quality — the most common reason a pilot is judged "too noisy". Three layers, deliberately not conflated:
  **disposition** (a fact about the past, no risk), **exception** (stops future matches — a deliberate
  coverage reduction, so audited, attributed, expiring, reviewable), **threshold** (fleet-wide, a config
  revision). The operator is always offered the *narrowest* layer that would work. Exclusion lists are
  already sanctioned as "a first-class policy primitive" in `openspec/config.yaml`.
  `Accept`: an exception is **dry-run against the retention window before it exists**, and the dialog states
  how many alerts it would have suppressed **including how many were dispositioned TRUE POSITIVE**. Default
  TTL 30 days; never-expiring needs admin + separate confirmation; **expiry RESTORES detection**.
  **Four security requirements, the first decided before shipping because retention forecloses it:**
  (1) **an exception NEVER prevents the alert being written** — it is written with
  `suppressed_by_exception_id` and hidden from the queue *view*, or an insider gets **retroactive
  deniability**, which beats blindness, and "this exception was malicious" stops being a query;
  (2) a reserved **non-exceptable rule class** (view-audit anomaly, export audit, agent-overdue, four-eyes
  denial, ledger integrity, exception lifecycle) enforced by `CONSOLE-40`'s guard, or the tuning surface is
  **self-concealing**; (3) a **self-reference check** — "narrowest first" is a reliability property that
  inverts as a security one, since the narrowest useful exception is "this rule, on my host, for my
  account"; (4) reuse `approvals.go:119`'s in-predicate `requester <> approver` and show the approver the
  effect **attributed to the proposer**.
  *Residual:* the dry-run is blind before `CONSOLE-40` — it must render the window it could evaluate and
  show the true-positive count as "≥ n"/"unknown", never a confident zero.
- **CONSOLE-42 · Detector health + exception register** — CONSOLE-41 · M. Per rule: fired, FP%,
  dispositioned population, active exceptions, trend sparkline **annotated with tuning events**. FP% renders
  **with the population it excludes** and is de-emphasised below a sample threshold — the honesty SOAR-6
  applies to MTTA/MTTR. Sorted by noise contribution (`fired × FP%`). The register shows each exception's
  **suppressed count since creation**: zero after 30 days means delete it; thousands means fix the detection.
- **CONSOLE-43 · Quiet start — a NOTIFICATION control, not an enforcement one** — CONSOLE-41 · M.
  **Rewritten after review; the first version was a blocker.** It said detections *"raise but do not enforce
  or page"*, one click, no tier, no expiry — a larger enforcement reduction than anything else in the
  console, reached around the gate ADR-15 exists to impose. What ships: **enforcement is never touched**;
  the window holds **routed notifications** (SOAR-9 sinks) while alerts and incidents are still created and
  dispositionable. Responder tier, **mandatory expiry (max 14 days)**, required reason, one audit row,
  **automatic restoration**. `Accept`: mutation — make it suppress enforcement rather than paging → a test
  asserting the endpoint still refuses a matching action must fail.
- **CONSOLE-26 · The queue as a worklist: assignment + bulk** — CONSOLE-4 · M. Without it the MVP is a
  viewer: SOAR-2's lifecycle is attributed but nothing says *whose* an incident is, and a 200-incident
  phishing wave is 200 round trips. Bulk returns **per-item results**, writes **one audit row per item**,
  and bulk containment is refused **as a whole** if it would exceed SOAR-7's blast-radius ceiling. Needs
  `select all matching filter` — `⌘A` is select-*page* and the grid is keyset-paged. **State in the ticket
  that assignment is workflow, not measurement**, or it gets refused for colliding with SOAR-6's deliberate
  refusal of per-analyst metrics as workforce surveillance.
- **CONSOLE-28 · Export from every grid** — CONSOLE-5,6 · S. Cheapest table-stakes item on the list, and it
  **strengthens** the boundary `CONSOLE-5` defends: a bulk export *is* "scroll the fleet and leave nothing",
  so it is view-audited with row count and filter, and is the natural first signal for per-viewer volume
  anomaly detection.
- **CONSOLE-12 · Hunt, Fleet, Explain + the pivot spine** — CONSOLE-6,8,9,10,11 · L. The five verbs —
  pivot, search, compare hosts, replay, explain a block — served by ⌘K palette, a global time range in the
  URL, a pivot menu on every value, every view URL-addressable so an IR handoff is a pasted link, and the
  whole loop completable by keyboard. *Split-pane compare deferred to `CONSOLE-39`; the standalone Entity
  page folds into the incident detail's entity panel, `CONSOLE-9`'s API unaffected.*
- **CONSOLE-14 · Assurance gates** — CONSOLE-12 · M. **Exit criterion.** Clicks-to-answer budgets asserted
  in Playwright and CI-gating, with the counting unit defined (*committed interactions*: pointer activations
  plus field commits, excluding characters typed) and budgets **derived by walking the specified dialogs**,
  covering the **safe** path including guards — a budget that excludes the guard turns the gate into
  pressure to delete it. Keyboard and pointer paths budgeted separately. axe/WCAG 2.2 AA; contrast unit test
  over the **named** token pairs in UX spec §11. **Golden-response fixtures, not generated types** — most
  handlers return anonymous `map[string]any`, so a generator degrades into "generate a few, hand-write the
  rest". *Workflows 7 and 8 are excluded from this gate: they depend on `CONSOLE-35` and `-20`, Phase 3.*
- **CONSOLE-15 · Console in the signed release** — CONSOLE-2 · M. **Exit criterion.** JS SBOM generated
  **from the lockfile** and fed into `BuildSBOM` so the manifest signature covers it —
  `internal/release/sbom.go:55` derives from `debug/buildinfo` and would describe zero npm packages.
  Node/pnpm pinned in the manifest beside the Go toolchain. Security-header audit on the served console.

### Phase 3 · Deferred — on the roadmap, not gating the MVP console

**Sequencing note on i18n, for the owner to overrule.** Multilingual support is an owner requirement and is
not in question — framework, ICU, signed bundles and the refusal of the unsigned overlay all stand. What
moved is *when*: the plan's own residual concedes the security narrative stays English until `I18N-2`, so a
Phase-2 `CONSOLE-13` would ship translated chrome above English alert reasons. The two things that cannot be
retrofitted — logical CSS properties and the no-bare-string lint — are in `CONSOLE-2`, Phase 0.

**Surfaces**

- **CONSOLE-16 · Standalone Overview dashboard** — CONSOLE-7 · M. Tile grid where every tile is a saved
  query. (MVP ships a health strip on Incidents.)
- **CONSOLE-17 · Alerts as a first-class page** — CONSOLE-6 · M. Dedup by `dedup_key`, ATT&CK mapping, ack.
- **CONSOLE-18 · Response surface** — CONSOLE-19 · L. Playbook definitions and runs, integration runners,
  notification routing.
- **CONSOLE-19 · Playbook read/validate/dry-run over HTTP** — new work · M. Playbooks are a polled file
  (`OPENSHIELD_PLAYBOOKS`) with no API. Read and dry-run first; authoring is a separate decision.
- **CONSOLE-20 · Evidence & ledger browser** — new work · M. Chain verification, anchors, witness,
  restore-drill history, and the view-audit reader.
- **CONSOLE-21 · Configuration UI** — new work · M. Schema-driven forms over `GET /config/schema`; bootstrap
  read-only with origin, dynamic editable; diff before save, revisions and rollback; secrets never readable
  back; **all field errors at once** because the API already reports them at once. What PLAT-5's derived
  schema was built for (D262/D263).
- **CONSOLE-22 · Administration & integrations** — new work · L. Role management, enroll-token issue/revoke,
  feed ingest and status, fleet-control publish — **all CLI-only today**, each needing an HTTP route with
  four-eyes where the CLI relied on shell access as the gate.
- **CONSOLE-39 · Split-pane compare** — CONSOLE-12 · M. Two hosts or two incidents side by side with
  independent time ranges. Deferred from the MVP spine, not refused — "compare hosts" is one of the five
  named verbs, and two URL-addressable tabs are the interim answer.
- **CONSOLE-52 · End-user directory** — CONSOLE-9,51 · L. *Was specified in the UX spec with no ticket
  anywhere — a surface claimed ✅ in the coverage matrix with no number, size, phase or owner.* Operators run
  the console; **end users are the people whose endpoints are protected** and the subjects of DLP decisions,
  UEBA baselines, entity risk and DSAR. Per user: IdP identity, devices with attestation and posture, risk
  over time, access grants, open incidents, DSAR record. Compiled subject view needs `privacy-officer`. The
  leaver check — what still references them after SCIM deprovisioning — takes the full destructive-action
  ceremony (summary, step-up, confirm, one audit row per object), **not the single click an earlier draft
  specified**.

**Detection administration** — *every domain that detects has a shipped, tested detection plane and no way
to see or change what it detects on without editing a file on a host. These close it, over one shared
component family. None gate the MVP console; together they gate "an administrator can run this product from
the console", which is a different and later claim.*

- **CONSOLE-46 · The rule-source component family** — CONSOLE-12 · M. One list component: origin (file /
  URL / operator), signature state where the artifact is signed, last reload, hot-reload vs restart, dry-run,
  diff-and-approve. **Reused five times, not five bespoke pages** — specified once so `-47`…`-50` are
  assembly.
- **CONSOLE-47 · Endpoint control** — CONSOLE-46 · M. Exec allow/deny and default-deny whitelisting
  (D217/D224/D230), FIM baselines (D223/228/229/236), canary placement (D232), USB enforcement.
- **CONSOLE-48 · Network defense** — CONSOLE-46 · M. IOC feeds, content signatures, DNS sinkhole lists, CASB
  catalog, TPROXY scope. Signature state matters: D297 fixed the gateway reading its IOC feed unverified, so
  the surface must render verified-before-parse rather than imply it.
- **CONSOLE-49 · DLP classifiers & indexes** *(absorbs `CONSOLE-23` policy/packs)* — CONSOLE-46 · L. EDM/IDM
  index lifecycle with **signed indexes (ADR-9)**, detector breadth per national ID type, compliance packs in
  force with a most-restrictive-wins lattice preview and simulation, exfil-channel coverage.
- **CONSOLE-50 · Device trust operations** — CONSOLE-8 · M. Enrollment tokens and self-enrollment status,
  attestation verdict history, **measured-boot PCR policy** (a typo in a PCR list silently narrowed
  attestation once, D413 — a surface showing the effective PCR set is the guard), attestation TTL,
  re-attestation failures.
- **CONSOLE-51 · Privacy operations** — CONSOLE-1 · M. DSAR request → compile → deliver as a workflow rather
  than a `/subject?id=` link; legal holds with what they block and who released them; retention and purge
  status; erasure verification. Gated on `privacy-officer`.

**Zero Trust** — *closes ZT-5's UI half, which the roadmap already said "ties to the UI (PLAT-1)".*

- **CONSOLE-44 · Catalog + effective-access matrix** — CONSOLE-9 · L. Today the catalog is
  `OPENSHIELD_ACCESS_CATALOG` (`internal/gateway/catalog.go:16`) and the policy a **Rego module**
  (`cmd/openshield-gateway/main.go:349`) — both files, and *"who can reach the production database?"* is
  answerable only by reading Rego. Services tab keeps HTTP reverse-proxy and TCP CONNECT distinct because the
  code refuses to interchange them; the **matrix reads in both directions** and **every cell is explainable**
  through `CONSOLE-10`'s trace; catalog↔policy drift surfaces.
  **Catalog writes carry the same diff + four-eyes as policy writes** — gating `-45` and not this is gating
  the harder attack: `ParseCatalog` accepts any `name=url` that parses, and a `tcp://` entry is an
  **uninspected** tunnel, so an ungated edit adds `tcp://169.254.169.254:80` or `tcp://prod-db:5432` and gets
  an authenticated, policy-brokered tunnel from the gateway's network position. Adding a `tcp://` entry is a
  **distinct, higher-privileged operation**; destinations validate against declared topology nodes (`TOPO-1`)
  rather than "does it parse"; link-local and loopback refused unless declared. **The matrix is the most
  valuable reconnaissance artifact in the deployment** — admin tier, **view-audited before the result
  returns**, rate-limited, feeding `CONSOLE-5`'s volume anomaly.
- **CONSOLE-45 · Policy authoring + sessions** — CONSOLE-44, SEC-C · L. Rego stays the source of truth and
  **the console never becomes a second authoring model that drifts from it**. Editor is the real module, with
  a dry-run evaluator and **diff + four-eyes on save**. Sessions: active principal/device/service and
  **terminate one or all** — what an IR lead needs at 2am and cannot do from anywhere today (responder tier,
  deliberately: admin builds a control nobody on shift can use).
  **Three review requirements.** The first is now UNBLOCKED, not outstanding: `SEC-C` (D464) made
  default-deny structural, so an edit shadowing one line no longer converts the gate — and `NewAccess`
  is the constructor a save path must use, its `ErrAccessPolicyAdmitsUnknown` the refusal it must
  surface. `SEC-D` (D465) supplies the other half a save needs: `AssessFourEyes` makes "refuse to enable
  a four-eyes gate unless operator identity is hardened" expressible. Still outstanding: **hot-reload
  with fail-static** (compile → assert the module denies a canonical unknown-principal input — which
  `NewAccess` now does, so this is a call rather than new logic → swap
  atomically → keep last-good → alarm), because the policy is `fatal` on compile failure and read once at
  startup, so a browser editor otherwise makes one bad save a **single-credential production-access DoS**;
  and the **dry-run evaluator is an access oracle** — it enumerates who reaches production with no
  access-proxy decision generated, so it is invisible to the telemetry edge health relies on, and its *rule
  path* output tells an attacker which predicate to satisfy. Admin tier, view-audited, rate-limited.
  *Session recording stays owner-gated: it carries a DPIA weight this product should not assume.*

**Capabilities that ship with no operator surface** — *found by auditing all 77 declared capabilities in
`openspec/specs/` against the plan (`scripts/plan-coverage-audit.py`) rather than by designing an
information architecture and hoping it was complete. Four of these five were invisible in every previous
version of this plan; `peer-ueba`/`CONSOLE-53` is the fifth and is above.*

- **CONSOLE-54 · ATT&CK coverage** — CONSOLE-17 · M. Technique mapping ships (SIEM-7/D201) and
  *"what is my ATT&CK coverage?"* — the question every SOC manager is asked by their board — has no answer
  in the product. A matrix over observed techniques, what detected them, and **what is mapped but never
  fired**, which is the half that matters and the half a vendor-supplied heatmap always overstates. State
  the limit inline: coverage means *"a rule maps to this technique"*, never *"you are protected against it"*.
- **CONSOLE-55 · Fail-open events** — CONSOLE-8 · S. Every timeout-allow emits a high-severity audit event
  by design (D17), because fail-open is mandatory for stability and is itself a bypass. **There is nowhere
  to see them.** That makes the product's central honesty mechanism invisible: the one signal that says
  "enforcement did not happen and we are telling you" is written and never read. A filtered view with rate,
  the path or gate that opened, and the budget it blew — and it belongs beside break-glass, because both
  answer "is this thing actually enforcing right now?"
- **CONSOLE-56 · Discovered objects (DSPM)** — CONSOLE-46 · M. DSPM-1 shipped (D371) and nothing lists what
  was discovered or where sensitive data sits. A discovery connector with no surface is an unwired feature
  with a passing test — the exact pattern `docs/unwired-audit.md` exists to catch.
- **CONSOLE-57 · Product observability at operator tier** — CONSOLE-7 · M. `/metrics` sits behind a separate
  constant-time bearer token (PLAT-4b) on a separate listener, so **the product's own telemetry is
  unreachable from an operator session**. `CONSOLE-7` covers health facts; this covers the counters —
  including the ones this repo keeps discovering are rendered by nothing (D415/D417/D418). Deliberately not
  a Grafana replacement: the operator-tier view is the counters that explain *this console's* answers, and
  Prometheus scraping stays where it is.

**Enterprise & adoption**

- **CONSOLE-30 · Custom roles / per-capability grants** — CONSOLE-1 · M. A capability table behind the
  existing `requireTier` seam, so the grant is data. Procurement asks for this by name in an access review.
- **CONSOLE-31 · Reporting: scheduled, exec PDF, compliance evidence packs** — CONSOLE-20 · L. Mapped to
  SOC 2 CC7 / ISO 27001 A.12 / PCI 10 / HIPAA §164.312(b). **Where the differentiator becomes an artifact:**
  a report rendered server-side, deterministically, with a hash-chain-verifiable evidence appendix is
  something the incumbents cannot produce.
- **CONSOLE-32 · Audit egress to the customer's SIEM** — new work · S. OpenShield ingests CEF, syslog,
  CloudTrail and WEF and **emits nothing**. One CEF/syslog emitter over the existing audit rows. A
  SIEM-ingesting product with no audit egress is a contradiction an evaluator finds in the first call.
- **CONSOLE-33 · Onboarding, empty states, deployment self-diagnosis** — CONSOLE-7 · M. A fresh install
  shows an empty queue, **indistinguishable from a broken install**. `-7` delivers health *facts*; this
  delivers a *diagnosis*. For an open-source product where adoption is the distribution channel, plausibly
  the highest-ROI item in Phase 3.
- **CONSOLE-34 · OpenAPI validated against the golden fixtures** — CONSOLE-14 · S. §10 rejects *generated
  types* for good reason, but that leaves no published contract, and "send us your API docs" is question two
  on every RFP. Promotes the fixtures from a private test artifact to a conformance corpus.
- **CONSOLE-35 · Shared team views + watchlists** — CONSOLE-12 · M. Saved searches are personal (SIEM-14);
  no manager-curated triage view, no watchlist for VIPs or crown-jewel hosts. Watchlists feed entity risk
  (D255) rather than being a UI filter, or they are decoration.
- **CONSOLE-36 · SLA timers + breach alerting** — CONSOLE-26 · S. SOAR-6's own residual names this gap: the
  console renders historical MTTA/MTTR while showing nothing about the incident aging in front of the
  analyst. Breach routed through SOAR-9's sinks. TABLE-STAKES for an MSSP.
- **CONSOLE-37 · Multi-tenancy** — CONSOLE-1 · XL · 🔒 owner decision. ADR-4 defers it and
  `docs/enterprise-gap-assessment.md` §3 names zero tenant scoping as evaluation-ending. `CONSOLE-1` reserves
  the seam so this is a `WHERE` clause; whether to build it is positioning, not engineering.
- **CONSOLE-38 · VPAT, browser support matrix, theming seam** — CONSOLE-14 · S. `-14` funds the real
  accessibility work; the **VPAT is the artifact procurement requests** and is a document, not a project.
  Theming via CSS custom properties is near-free during `-2` and expensive after fourteen components ship.

**Freshness, security and i18n follow-ups**

- **API-9 · Streaming (SSE), if a measured need appears** — 🔵 deferred by decision, not backlog. Cut from
  the MVP: correlation runs on a CLOCK (SOAR-2/D250) so streaming buys latency the backend does not produce,
  and a long-lived stream authorizes once at handshake — reintroducing the role staleness ZT-7 deleted
  (`operator_roles.go:26`). MVP polls with ETag/`If-None-Match` at 10–15s. *Residual:* freshness is bounded
  by the poll interval **and** the correlation interval, and the second dominates. If it lands, the stream
  loop must re-resolve the role on a tick, tear down on mismatch, and cap lifetime below session idle.
- **CONSOLE-24 · Session sender-constraining** — CONSOLE-3 · M. Non-extractable WebCrypto keypair or DBSC,
  so `REQUIRE_DPOP=1` no longer has to refuse console login. Until then the refusal is the honest answer.
- **CONSOLE-13 · i18n foundation** — CONSOLE-4 · M. `react-i18next` + ICU; **bundles embedded and signed
  with the release, never loaded from a mutable directory** — an unsigned hot-loaded pack rewrites UI text
  including the four-eyes button label, and `threat-model.md:193` requires signatures before parse.
  Approval confirmations and destructive-action labels live in a **non-overridable embedded namespace**.
  Gates: `en-XA` pseudolocale render test (the lint rule is in `CONSOLE-2`). *Residual:* backend-emitted
  reason strings stay English — "the console chrome is localizable; the security narrative is not yet".
- **I18N-2 · Localizable security narrative** — CONSOLE-13 · L. Message IDs + params at the emission point
  instead of pre-formatted English, so alert reasons and policy explanations localize. The half that makes
  "multilingual" true rather than "the chrome is translated".
- **UI-19 · Signed locale packs** — CONSOLE-13 · M. Verified against the operator key before parse, same
  loader as rule bundles and IOC feeds; `{lng}`/`{ns}` pattern-matched and resolved under the root; the
  non-overridable namespace still wins. The **unsigned** overlay is REFUSED, not deferred.

---

## 🗺️ Lane G · Topology — declared, compiled, delivered

Spec: `docs/superpowers/specs/2026-07-31-topology-canvas-spec.md`. Sequenced after the console MVP; it
serves none of the five adoption verbs. There is no topology, site or zone concept today
(`grep -riE "topology|site_?id|zone_?id"` over `.go` returns nothing). ADR-15.

**The governing sentence: the canvas is a view of a reconciled model, not a drawing of a network.** Three
rules follow — you cannot delete reality from it (deleting a discovered node removes your *declaration*; the
node stays, marked `undeclared`); an edge is an assertion of intent, never an act; and the canvas never
applies anything. **A node is a ROLE with a population, and also a CONFIGURATION IDENTITY** — one
`user endpoints` node for all 51 laptops, editing it edits all of them, and hosts configured differently
belong to different nodes.

**Configuration delivery is a Lane D concern, not this lane's:** `PLAT-5c`/`-5d`/`-5e`. `TOPO-3` ships
export as the interim path.

### Lane G index

| ID | Ticket | Depends | Size |
|---|---|---|---|
| TOPO-1 | Topology model + drift *(drift needs no canvas)* | CONSOLE-8 | L |
| TOPO-2 | The canvas | TOPO-1 | L |
| TOPO-2c | The node as a configuration surface | TOPO-2 | M |
| TOPO-3 | Routing compiler + export | TOPO-1 | L |
| TOPO-2b | Coverage meter, live during editing | TOPO-2, -3 | M |
| TOPO-6 | Edge health *(passive)* | TOPO-1 | L |
| TOPO-7 | Active reachability probes *(opt-in, off)* | TOPO-6 | M |
| TOPO-8 | Unmanaged sources | TOPO-6 | S |
| TOPO-4 | Topology-driven configuration delivery | PLAT-5c | 🔒 L |
| TOPO-5 | Apply from the canvas | TOPO-4 | 🔒 L |

- **TOPO-1 · Topology model + drift** — CONSOLE-8 · L. **A node is a ROLE, not a machine** (owner decision,
  2026-07-31, and it is what makes the whole lane tractable): one `user endpoints` node stands for all 51
  laptops, one `internet` node for all external traffic. Membership is a **predicate** stored in the model
  (platform, tag, OU, subnet, site); population is an attribute — a count, a health distribution, a member
  list — and **never becomes geometry**. Consequences: a real deployment is 8–20 nodes so the scale
  machinery an inventory graph needs is not built; the diagram matches how operators already whiteboard;
  and the model stops churning as endpoints come and go, **which is what makes drift meaningful — a graph
  that always changes cannot show change.**
  **A node is also a CONFIGURATION IDENTITY** (owner decision, same date): it holds every host sharing one
  configuration, editing it edits all of them, and hosts configured differently belong to **different
  nodes**. That replaces an earlier, worse idea in which a node displayed the *distribution* of differing
  values — a distribution renders a symptom as a feature, telling an operator their fleet is inconsistent
  while offering no way to say what it should be. Four rules follow: one host is in exactly one node per
  config domain (or "edits all of them" is ambiguous); **overlapping predicates are a validation error
  refused at save**, never resolved by precedence; a member whose observed config differs from the
  declaration is drift with two honest resolutions — re-apply, or **`Split node`** as a first-class
  operation, because a deliberate difference *is* a different configuration; and new members joining by
  predicate are **announced, never silent**.
  **Discovery is call-home, so the inventory is complete and "not yet placed" is an explicit state.** Every
  component enrols and reports, so nothing is guessed and no scanning is needed. Everything that called home
  is either on a node or in the **unplaced tray** — a completeness meter whose empty state genuinely means
  the model accounts for everything deployed. This replaces the weaker framing of "we might not know about
  things" with "here is precisely what you have not accounted for".
  Typed kinds (control-plane server · worker · gateway in one of four modes: egress proxy, ZT access proxy,
  inline TPROXY, DNS sinkhole · user endpoints · internal service · external network · identity provider ·
  broker · database · integration sink · site/zone). Every node is **discovered** (bound by canonical device
  identity, IDENT-1/ADR-6) or **declared**. Edges are typed and typechecked: `routes-traffic-to`,
  `protected-by`, `enrolls-with`, `publishes-to`, `authenticates-against`. Revisioned like PLAT-5 config —
  author, diff, rollback, audited. **Drift ships here and needs no canvas**: declared-but-not-enrolled,
  enrolled-but-not-declared, agents matching no node, and gateways enforcing rules the topology does not
  declare — as a list on the Fleet page. Without drift this is a drawing tool.
- **TOPO-2 · The canvas** — TOPO-1 · L. Spec: `docs/superpowers/specs/2026-07-31-topology-canvas-spec.md`.
  `@xyflow/react` node editor — the only ticket that justifies the canvas dependency, charged here rather
  than to the console's budget. **Governed by one sentence: the canvas is a view of a reconciled model, not
  a drawing of a network** — so (1) you cannot delete reality from it (deleting a discovered node removes
  your *declaration*; the node stays, marked `undeclared`), (2) an edge is an assertion of intent, never an
  act, and (3) the canvas never applies anything. It is **not n8n**: there the graph *is* the program, here
  nodes exist whether or not you drew them. Binding state is border geometry (solid / dashed / double), not
  colour, because severity owns colour — so severity chips are the only thing that draws the eye across a
  large graph, which is the intent. **Scale is a design requirement, not a rendering detail**: endpoints are
  never individual nodes (role aggregation is a `TOPO-1` model decision), and past ~60 nodes the canvas
  **refuses to auto-layout and says why** rather than rendering an unusable hairball. *(Corrected: an
  earlier version said "semantic zoom has three tiers" and "above 150 nodes" — both were written before the
  node-is-a-role decision made that machinery unnecessary. The spec is authoritative.)* Deterministic layered layout — a force-directed graph that settles differently each load
  destroys the spatial memory that is the whole reason a map beats a list. `Accept`: the tree view is
  **co-equal and fully editable**, not an accessibility fallback — it is the screen-reader path, the
  keyboard path, and the faster path for bulk edits, which is what stops it rotting.
- **TOPO-2c · The node as a configuration surface** — TOPO-2 · M. The console has **133 config fields**
  and the Settings IA groups them correctly but still asks the operator to know where a thing lives. The
  topology gives the same fields a **spatial index**: click the gateway in front of production and configure
  that gateway; click `user endpoints` and configure the policy that population receives. **The panel renders
  the same schema-driven forms as Settings** (`GET /config/schema`) — one renderer, two entry points, so a
  field added in Go appears in both and no diagram needs updating. Scope is stated **on the node before the
  edit**, because it differs sharply and silently (gateway = bootstrap, node-local, restart; server = mostly
  dynamic, cluster-wide). **The node's value IS the declaration for every member** — no distribution
  display, no per-host override reachable from here; a field has one declared value and a member that
  differs is drift with two named resolutions (re-apply, or split). Declared and observed render side by
  side — *"47 of 51 match · 4 differ"* — and zero drift shows a quiet confirmation rather than nothing,
  because "everything agrees" is information. **What "applies to all" means today, stated precisely:** the
  edit declares the configuration for every member; *delivering* it is `PLAT-5c`'s signed channel once that
  lands, and `TOPO-3` export until then. The panel never implies a save reached a host.
- **TOPO-3 · Routing compiler + export** — TOPO-1 · L. A **pure function**: graph → *proposed* gateway
  configuration plus CASB/policy/feed catalogs, with a validated per-node diff. Generates, never applies.
  Pure means directly testable: given a graph, assert the emitted config. Output leads with the **semantic
  summary** ("prod-web loses inline inspection"), because ADR-15 requires approval to be semantic and
  nobody approves a field diff by inspection.
  **Ships with EXPORT as the interim path, explicitly labelled interim.** Until `PLAT-5c` there is no
  dynamic scope on endpoints or gateways to deliver into, so the compile output ends with an honest terminal
  state — *"delivery is not available yet; export it or apply it through your existing configuration
  management, and the canvas will show each member converge"* — rather than a greyed-out `Apply` implying it
  is nearly ready. A validated, typechecked, coverage-checked config from a reconciled model is genuinely
  useful with Ansible or a Containerfile, **so Lane G delivers value before `PLAT-5c` and `TOPO-4` land.**
  But export is not the destination: **a configuration surface that requires shell access on every host is
  not a configuration surface.**
- **TOPO-2b · Coverage meter, live during editing** — TOPO-2,3 · M. ADR-15 requires a coverage-reducing
  change to be expressed as `ENFORCEMENT_DISABLE`. The UX consequence is that **coverage loss must be
  visible at the moment of the edit, not at approval** — an operator who learns at approval time has
  already built a change set around a false assumption. A live meter in the toolbar (inline inspection
  *n/m* services, sinkhole *n/m* zones, ZT-fronted *n/m*), and an edit that reduces it stops and offers
  `Undo` or `Continue and request ENFORCEMENT_DISABLE`. They can still do it; they cannot do it quietly.
- **TOPO-6 · Edge health — is the network operating as described?** — TOPO-1 · L. Drift asks whether
  configuration matches declaration; this asks whether **traffic is actually flowing the way the model says
  it should, right now**. It is what turns the canvas from a reconciliation tool into a monitoring surface.
  **Tier 1 only: passive, derived from telemetry already flowing, generating no new traffic** — agent
  heartbeats, gateway/access-proxy decisions naming an upstream, JetStream consumer health, per-service
  allow/deny counts. Four states, and **`silent` and `failing` must never be merged**: silent means the path
  is not being used (routing change, dead upstream, stopped agent); failing means it *is* being used and
  refused — which is often default-deny working correctly. Conflating them sends operators to the wrong
  place. **"Expected" is declared, never inferred**, because inferring expectation from history silently
  reclassifies a path that broke last week as normal.
- **TOPO-7 · Active reachability probes** — TOPO-6 · M · **off by default, per-edge opt-in.** Passive cannot
  separate "nobody tried" from "it is broken" on a quiet path. The reason for the opt-in, stated plainly:
  **a security product that probes internal services generates exactly the traffic it is built to detect** —
  unscoped it trips the customer's other controls, pollutes its own telemetry, and looks like reconnaissance
  in someone else's SIEM. So: declared-node → declared-node only (the same allow-list discipline that keeps
  the access catalog from being an SSRF pivot, never arbitrary addresses), rate-limited, carrying a stable
  identifying marker, attributed to the operator who enabled it, and **excluded from detection and from UEBA
  baselines** — or the product alerts on itself and skews the baselines it uses to find real anomalies. The
  canvas always shows **which tier produced a state**, because "we saw real traffic" and "our probe
  succeeded" are different evidence.
- **TOPO-8 · Unmanaged sources** — TOPO-6 · S. The one real blind spot in call-home discovery: a host that
  never installed an agent is invisible to enrolment — but **not** to the gateway, which sees traffic from
  sources mapping to no enrolled identity. Surfaced as a count with its caveat rendered in place: inferred
  from observed traffic, sees only what traverses a gateway, **not an inventory**. Its own ticket rather
  than folded into discovery, because a soft inference and a hard enrolment must never render as the same
  kind of fact.
- **TOPO-4 · Topology-driven configuration delivery** — PLAT-5c · 🔒 **owner-gated** · L *(was XL: with
  `PLAT-5c` carrying the channel, this becomes the topology-shaped layer over it rather than new
  transport)*. Gateway config is node-local with no database credentials (D272), so delivery rides the
  signed channel rather than the config DB. Three constraints are the whole design: **(1)** it must not become a second
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
- ~~**NIPS-5 · HTTP/2 & QUIC interception**~~ — **SHIPPED.** HTTP/2 intercepts through the same
  pipeline as HTTP/1.1; QUIC landed as NIPS-12 with its own inline plane (`OPENSHIELD_QUIC_PLANE`),
  because UDP needed a different data path rather than a different ALPN string. Do not re-propose.
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
### Broker lifecycle — found by the offline-queue recovery test (D367)
### Data-at-rest discovery (DSPM) — from the enterprise gap assessment
### Zero Trust
- **ZT-5 · Policy admin + session recording** — **now scheduled as `CONSOLE-44` + `CONSOLE-45` in Lane F.**
  This entry said "ties to the UI (PLAT-1)" and the first console plan missed it: the access catalog is an
  allow-list string and the access policy is a Rego module, both files, so *"who can reach the production
  database?"* is answerable today only by reading Rego. `CONSOLE-44` delivers the catalog and the
  effective-access matrix, `CONSOLE-45` the authoring and session termination. **Session RECORDING stays
  owner-gated and out of both** — it carries a DPIA weight this product should not assume, and it is a
  separate decision from policy administration.
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

- ~~**SEC-A · No configuration field declares a bound, and four dynamic fields already neuter the
  product**~~ — **SHIPPED D466; do not re-propose.** `grep "Validate:"` returned zero: the hook existed,
  both validation paths called it, and no field had ever declared one, so the entire bound was `Kind`
  parseability. Fixed in two halves, because a bound alone would not have been enough. **Ranges** on the
  fields gating a detector or a retention window, each refusal naming what BREAKS rather than which limit
  was exceeded. And a **direction** (`Sensitivity`) on all seventeen, making "this change moves toward
  less detection" computable — which is the half that matters, since most of the attack uses values that
  are reasonable in isolation (a 24h retention is a legitimate choice and a suspicious one on the day an
  incident is opened). A weakening change now **pages someone** and is **recorded on the revision diff**;
  a tightening one is silent, or the alert gets muted and takes the weakening one with it. The subtle
  case, with its own test: a DISABLING value orders as the weakest setting, not by magnitude — read as a
  number, `CORRELATE_INTERVAL=0s` is the smallest interval and the single change that raises no incidents
  at all would have scored as a hardening.
- ~~**SEC-B · The fleet-control replay bound is in memory, and the threat model says otherwise**~~ —
  **SHIPPED D462; do not re-propose.** `FleetControlSubscriber.applied` was a plain `uint64` with no
  persistence and no call site that could supply any, so an agent restart reset the bound to zero and
  every captured control replayed, bounded only by its TTL — while `docs/threat-model.md` claimed the
  sequence was *"stored rather than held in memory"*. True of the publisher; **false of the consumer,
  and the consumer is where replay is refused.** Now persisted by DEFAULT
  (`OPENSHIELD_FLEET_CONTROL_SEQ_FILE`), written BEFORE the control is applied, refused when it cannot
  be written, proven readable and writable at startup, and refused outright when pointed at the
  telemetry sequence file. Threat model corrected including the residual. *Proved end to end by
  capturing the control plane's own bytes and replaying them past a restart, with an in-memory gateway
  as the control group.*
- ~~**SEC-C · The access policy grants on no-match**~~ — **SHIPPED D464; do not re-propose.**
  `evalCandidate` returned `ACTION_ALLOW` with reason *"no policy rule matched"* and the access proxy
  grants on `ALLOW`, so **default-deny lived in the text of the operator's Rego, not in the engine** —
  and every access policy in the tree ends with the one line that provided it. `policy.NewAccess` now
  denies on no-match (a per-STAGE property: the endpoint DLP pipeline must keep allowing an unmatched
  event, or it blocks every ordinary file write on the host) **and** proves at load that the module
  denies a canonical unknown principal, in two shapes — nil context and zero context — because a
  `role != "banned"` predicate reads like a denylist and admits every caller whose role could not be
  resolved. That second half is not redundant: such a policy MATCHES, so no default can catch it. The
  gateway refuses to start on one. *Proved through the real binary: an incomplete policy denies an
  unmatched caller and still serves the authorized one; a permissive policy never opens the port.*
  **Upgrade impact, found by CI and worth stating:** a deployment whose access policy is keyed on
  something other than identity — the shipped `risk_test` fixture allowed whenever `risk_score < 0.8`,
  which admits a caller with no identity and therefore score 0 — will now FAIL TO START rather than
  keep admitting unknown principals. That is the intended failure mode, and it is a breaking change for
  exactly the policies that had the defect. (Credit where due, and keep it: the Rego capability restriction is
  genuinely well built — nondeterministic builtins filtered wholesale by flag, `opa.runtime` denied,
  `AllowNet` empty, so `http.send` from an authored policy is not expressible.)
- ~~**SEC-D · Four-eyes is capped by two shipped defaults**~~ — **SHIPPED D465; do not re-propose.**
  `OPERATOR_ROLES_STRICT=0` lets an identity with no server-side record fall back to its certificate
  (two operator certs are two operators) and `OPERATOR_OIDC_REQUIRE_DPOP=0` accepts an unbound token
  (two stolen tokens are two operators) — and four-eyes said nothing about either, so the trail attested
  to a control that may not have existed. **The defaults were not the defect and are unchanged**: their
  migration argument (turning either on before a deployment has migrated locks every operator out) still
  holds. What changed is that the control now says what it is worth. Every resolved approval RECORDS the
  assurance in force at that moment — at resolution, so hardening later cannot retroactively make old
  approvals look strong; every component STATES it at startup, naming each switch that is off and
  confirming when hardened; and `OPENSHIELD_FOUR_EYES_REQUIRE_STRONG=1` refuses to GRANT what it cannot
  attest to. **Denials are never gated** — refusing to record a "no" would keep the dangerous request
  pending and approvable while blocking the operator trying to stop it. `AssessFourEyes` is the
  primitive `CONSOLE-45` and `PLAT-5c` consult, so "must refuse unless hardened" is now expressible
  rather than a note here. *Honest residual: this distinguishes two IDENTITIES, never two PEOPLE.*

**🟠 UEBA has no maturity concept, and no operator surface at all (found 2026-07-31, by asking "where is
the UEBA dashboard?"). The answer was that the dashboard is the second problem.**

- **UEBA-1 · A baseline must know whether it is ready** — new work · M. `ueba_baselines` is
  `subject → (count, last_seen)` — one number per subject — and the alerting decision is a bare threshold
  (`internal/controlplane/signed.go:166`: `pc.RiskScore < s.peerThreshold`). **There is no minimum sample,
  no warm-up and no maturity state**, so a subject observed once can produce a deviation that pages a human,
  and a fresh deployment is at its noisiest exactly when its baselines are least trustworthy. Add a
  per-baseline maturity state (observations, span, last update) and a **minimum-sample gate below which a
  deviation is recorded but never alerts**, with the population it suppressed counted so the gate is visible
  rather than silent. Pairs with `CONSOLE-43` (quiet start) but is not the same thing: quiet start holds
  *paging* for a window an operator chose; this refuses to *claim significance* from a baseline that has
  none. `Accept`: mutation — remove the sample gate → a test asserting a one-observation subject does not
  alert must fail.
- **UEBA-2 · State the model's limits where they are read** — new work · S. What ships is a **peer-relative
  count-deviation detector**: no decay (a deviation stays sticky, XDR-7's residual), no seasonality or
  time-of-day, no multi-feature profile, and no inspectable peer-group model. The word "UEBA" invites
  Exabeam-class expectations, so the README, the maturity table and any surface must say what it is —
  the same discipline that made this project refuse "tamper-proof" for "tamper-evident between anchors".
- **CONSOLE-53 · Behavioral baselines surface** — UEBA-1, CONSOLE-9, CONSOLE-51 · M · Phase 3. Per subject:
  baseline value, observation count and span, **maturity state**, last update, current deviation against the
  threshold, and the alerts it produced. Operator acts: **reset a baseline** — the missing tool today, and
  the correct answer to a legitimate behaviour change (role change, new project), because the alternatives
  are suppressing the rule forever (which hides the next real signal) or waiting for drift; and tune the
  threshold, which is already dynamic config.
  **It is a privacy surface before it is an analytics one.** A baseline is a behavioural profile of a
  person: `subject` is a pseudonym and stays one, the de-pseudonymised view is `privacy-officer`, the
  baseline is included in the DSAR compilation and erased with it, and the page states plainly what is
  retained and for how long — this is works-council and DPIA territory, not a dashboard tile.
  *Deliberately not built:* no per-analyst view of who deviates most, for the same reason SOAR-6 refuses
  per-analyst metrics — that is workforce surveillance wearing an analytics label.

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
  **One use has an unusually good risk profile and is worth naming: topology review** (spec §8a). The
  topology is small, structured, operator-declared and **not attacker-controlled** — which is what separates
  it from every other AI use here, where the assistant reasons over data an attacker wrote. It would say
  things like *"prod-api is declared behind no gateway while every other service in this zone is behind
  gw-edge-01"* or *"7 enrolled agents match no declared node"*. Guardrails fall out of rules Lane G already
  has: it **proposes declarations, never applies configuration** — entering at exactly the point a human
  edit enters, inheriting the coverage check and the approval path unchanged; it cannot propose a coverage
  reduction without the `ENFORCEMENT_DISABLE` gate firing on it identically; every suggestion cites the
  observation it came from; and **it is never the source of a health verdict** — it may summarise a
  `silent`/`failing` edge, never produce one, because measurements must stay reproducible.
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
- **Assurance & docs:** `docs/threat-model.md` consolidated — eight boundaries, each naming its guard and
  the test that holds it, each stating its limit (D302); `INVARIANTS.md` — five invariants, each
  MUTATION-VERIFIED and each with its honest limit (D298); performance/latency budget in CI — the real-path
  exec decision fails the build when p99 exceeds the IPC deadline that decides whether a verdict is
  delivered (D301); the dnsredirect kernel tests de-flaked and actually running under real root (D382).
- **Broker lifecycle:** reconnect-forever on every long-lived process, replacing nats.go's give-up defaults
  (D368); endpoint partition + ping detection (D369); PLAT-10 — a broker returning with empty JetStream
  state no longer wedges the fleet silently, repaired by a POLL rather than a reconnect handler because a
  stream can be deleted while the connection stays healthy (D370).
- **DSPM:** DSPM-1 object-store discovery connector (D371); DSPM-2 bucket ACCESS CONTEXT rides every
  discovered object — ACL, bucket policy, block-public-access and default encryption probed once per
  sweep, three-valued so a credential that cannot read `?acl` yields UNKNOWN and never "private", with
  each refused probe named (D454).
- **Release / packaging:** the release publishes its own `.deb` and its systemd units are tested
  (D448/D449); packaging no longer makes the next `verify-release` report tampering (D447); an INSTALLED
  system can be checked against the release it came from (D450).
- **Endpoint / fleet:** the endpoint asks about ITSELF the posture question it asks about everything
  else (D451); fleet binary provenance — "which endpoints run binaries nobody published" is a fleet
  query (D452).
- **Detection breadth:** Spain's DNI/NIE and France's NIR (D453). Italy's Codice Fiscale deliberately
  absent rather than guessed — see the enrichment backlog.
- **ATT&CK / narrative correlation (the D455–D456 pair):** XDR-4b put the technique ids on the
  `Decision` — DERIVED from the platform's own signals, never read back out of a policy result, and
  refused by the contract if outside the closed vocabulary — so correlation can hunt `T1552 →
  T1567.002` rather than `dlp → hips` (D455). XDR-4c then made the ordered-sequence rules RUN ON THE
  CLOCK from a validated hunt file, with incidents keyed by (entity, rule) so two narratives on one
  asset cannot collide into one silently-updated row (D456). Before it, the sequence fields were set in
  exactly one place outside tests — the `GET /incidents` query parser.
- **Privacy (PRIV-1, D457):** `core.ExclusionSet` had zero non-test callers. Personal-folder prefixes
  and break-time windows are now configurable and enforced BEFORE classification; an exclusion never
  suppresses an enforcement verdict (that would be the user-invokable evasion the requirement forbids);
  and a path exclusion that cannot be evaluated is COUNTED, so the gap in the privacy claim is a number.
- **DLP correctness (D458):** `printDecider` and the clipboard mediator each ran the pipeline TWICE over
  one job — once for the verdict, once because the event was also enqueued — while `ContentStore`
  releases on read. The two runs raced for the only copy of the evidence, and when the observation loop
  won, the VERDICT was the blind one: no detection, allow, job printed. Both existing tests passed
  because they hand the decider a buffered channel with no consumer.
- **SEC-B — the fleet-control replay bound survives a restart (D462).** The refusal logic was correct
  the whole time and consulted a number that every new process initialised to zero, so waiting for a
  reboot was the entire attack against the most attractive forgery target in the system. Persisted by
  default, written before the control is applied, and refused when unwritable. Two further defects were
  found by *trying to prove it end to end*, which is the argument for scenario tests in one line:
  **D461** — a ledger anchored but never written to could not be reopened, so a process that started,
  recorded nothing and restarted could never start again, permanently and self-inflicted (`entryCount`
  was read and never used — the shape of a branch that was meant to be there); and **D462b** — the
  gateway's degraded counters, including the kill switch's suppression count, were reported only in
  ACCESS mode, which is an alternative to the proxy path rather than a stage of it, so the mode most
  gateways run in reported nothing. That block carried a comment about having been deliberately hoisted
  out of the NATS conditional to fix this exact defect; the hoist was right and one scope short.
- **SEC-C — the access gate's default-deny is now the gate's, not the operator's (D464).** The comment at
  the load site already claimed the property: *"never fall back to the observe-first default (which is
  default-ALLOW and would admit everyone)"*. It refused to fall back to a whole permissive POLICY, and
  then loaded the operator's policy into a stage whose no-match OUTCOME was that same default-ALLOW. The
  fix has two halves because the failures are disjoint — the rule that is ABSENT (a default answers it)
  and the rule that is PRESENT and wrong (only evaluating the module finds it) — and a third
  consideration that shaped both: an engine-wide default-deny would have been a worse defect than the
  bug, blocking every ordinary file write on every endpoint on the first deployment.
- **SEC-D and SEC-A — two more controls that were sound and consulted something worthless (D465, D466).**
  The whole SEC lane turned out to have ONE SHAPE: *the mechanism was correct and its input was not.* A
  replay bound that reset on restart, a no-match default that was right for one stage and wrong for the
  other, an identity string two credentials satisfy, and a configuration field whose only bound was
  whether it parsed. None of the four was a logic error; each was a correct check over a value that did
  not mean what the check assumed — which is also why all four were invisible to unit tests that
  construct their own inputs. **Look at the input, not the logic.**
- **The enriched config schema reaches the console (D467).** SEC-A added an operational range and a
  detection direction to `config.Field`, and `FieldDesc` — what `GET /config/schema` serves, and the only
  thing `CONSOLE-21` renders from — carried neither. A schema-driven form would have shown the settings
  that decide whether anything is detected at all looking exactly like the cosmetic ones: no range, no
  help, no sign which direction is dangerous. `Validate func(string) error` became a `Bound` struct
  carrying the check, the range as a person reads it and what exceeding it costs, **declared together**,
  because the alternative is a renderable range that drifts from the check the server enforces — and it
  drifts toward a form insisting a value is fine while the server refuses it. `/config/schema` also had
  **no test at all**; it has one now, asserted at the HTTP boundary, because "the schema carries it" and
  "the console can see it" are different claims and the gap between them is where D418's whole class of
  defect lives.
- **Lane F started, and it did not start with a UI (D468, D469).** Its first tickets are backend work —
  `CONSOLE-1` is a shipped SECURITY DEFECT, not console preparation: `requireTier` authenticated a
  bearer token and discarded the identity, so an SSO operator passed the tier gate and was refused by
  eight handlers that re-derived it from the TLS peer certificate. D373 shipped an authentication method
  that reached almost none of the product. **The obvious fix was the trap** — threading the token
  identity through unchanged lets one human request an approval from the CLI and grant it from the
  browser, because a certificate minted `operator:<CN>` and a token minted the raw `sub`. Since SEC-D
  that collapse would have been recorded as `strong` assurance. Fixed together, which is what the ticket
  meant by "fixes both or neither".
- **Identity / Zero Trust:** ZT-7 operator identity — SSO, the role out of the certificate, token binding and SCIM deprovisioning (D372/D373/D375/D379/D380). IDENT-1 canonical device identity (D170, ADR-6) — one shared pseudonym
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

### ⚠️ FOUND BY REVIEW OF D485, NOT FIXED THERE — the stop-exemption is in ONE of six leader loops

`RunCorrelationLoop` now exempts its own cancellation from `correlation_failures_total`. **Five sibling
loops under the same `leaderCtx` still count and log on cancellation**, so a demotion or restart still
lights up their counters and the metric family is inconsistent with nothing saying so:

| Loop | Counter |
|---|---|
| `beaconing.go:166` | `BeaconFailures` |
| `playbook.go:254` | `PlaybookFailures` |
| `escalate.go:221` | `EscalationFailures` |
| `cases_http.go:330` | `ApprovalExpiryFailures` (counted with **no log at all**) |
| `itsm.go:172` | `ITSMFailures` — the worst: `SyncITSM` makes outbound HTTP, so a shutdown mid-sync aborts a live request and books it as "the incident has no ticket where responders are looking" |

An operator comparing `correlation_failures_total` against its neighbours during an incident will read the
difference as signal. **Leaving them inconsistent is a worse answer than either uniform choice** — decide
explicitly rather than by omission.

Two further review findings, recorded rather than fixed:
- **`startCorrelationLoop`'s ordering is convention, not construction.** It relies on `t.Cleanup` LIFO
  putting the join before `pool.Close`, which holds only if it is called after `requireDB` on the same
  `*testing.T`. It takes a `*Server`, not the pool, so it cannot see the resource whose lifetime it
  orders against. Taking the pool (or returning a `stop()` to defer) would make it structural.
- **The new `e2e-verification` SHALL is violated by `internal/controlplane` today**: `nips6_test.go:197`
  and `soar4_test.go:584,:594,:604` leak loops against a `requireDB` pool. The counter half is not armed
  in those tests, but `nips6_test.go:197` runs real queries every 20ms into the *next* test's
  `DROP TABLE … CASCADE` + `Migrate` — a DDL/DML collision, not just a counter.

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

### The five tensions (T1–T5) — all resolved

Kept as one line each so a closed fork is not reopened by someone who did not see it close. The reasoning
is in `docs/decisions.md` and the ADRs above.

- **T1 — Does the closed action set (D14) expand?** *Resolved:* one typed verb per capability, never a
  parameterised framework. No per-verb gate is outstanding.
- **T2 — Does risk flow back to enforcement?** *Resolved in code:* the server computes and publishes risk;
  the endpoint and gateway read it as typed Policy context (D28) and decide locally. **The server informs;
  it never actuates.**
- **T3 — One product or a platform?** *Resolved:* the platform bet is made — OpenShield is an XDR, DLP is
  one classify-domain. The discipline is **depth beats shallow breadth**; new domains enter as explicit,
  separately-scoped bets, never a core change.
- **T4 — Categories that do NOT fit (NAC/VPN).** *Resolved by the owner: PARKED* — ADR-0.
- **T5 — Does SOAR make the server a controller?** *Resolved, tiered* — ADR-12. Arbitrary endpoint command
  execution and remote content pull are permanently out.

