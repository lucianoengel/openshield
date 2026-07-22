# OpenShield architecture roadmap

> Companion to [`decisions.md`](decisions.md). Two things live here: the **current build
> state** (what's done, what's next) at the top, and the **design rationale** (the pipeline
> lens, the frozen core, the tensions, the phased plan) as reference at the bottom. The middle
> holds the **architecture decisions** that close the open forks and the **category backlog**.
>
> **Authoritative status is this file at `HEAD`, as of the Round-32 audit (verified through
> D168, 2026-07-22).** Earlier round-by-round narratives have been folded into the Done list
> and the queue below; see *Audit history* at the end for what each round covered.

---

## How the builder consumes this

- **Re-verify before proposing.** The repo moves fast (a builder commits concurrently). Open the
  cited files at `HEAD` and confirm the gap still exists before starting a ticket. Line numbers are
  as-of-audit and drift — treat `file:symbol` as the anchor, re-locate if a line moved.
- **Work the queue in order.** *Next — the active queue* below is prescriptive. Finish it before
  pulling from *Backlog by category*.
- **One OpenSpec change per ticket** (`openspec-propose` → implement → `openspec-archive`). Ticket
  IDs (`IDENT-1`, `DLP-5b`, `ADR-6`…) are stable handles — use them in the change name and commit.
- **Every acceptance test must drive the REAL runtime path**, never a mock built from the code's own
  assumptions. This project's signature failure is *"verifies against its own assumptions"* — a test
  that passes because it shares the code's wrong premise (it has recurred in nearly every audit
  round; see the queue). For each negative security property, add the **mutation that would let the
  bug through** and prove the test catches it.
- **The frozen core governs.** If a ticket seems to force a change to `core.Dispatcher` / `State` /
  `Stage` / `Registry` / the `Enforcer` interfaces / `OnOutcome` / the ledger / the D10/D29 content
  boundary, STOP and re-run the D26/D69 fitness reasoning — capability lands as a producer, classify
  plugin, typed context, or one deliberate action, not a core change. See *Reference* below.

---

## Status at a glance (Round-32, verified through D168)

**OpenShield is a pipeline-native XDR** — one Event→Classify→Policy→Decision→Enforce→Audit pipeline
spanning **endpoint, network, and identity**, with correlation and response (SIEM incidents/UEBA + the
hash-chained evidence ledger) above it. DLP is one detection domain among several, not the product's
center of gravity. Every domain below is partial; the work is depth-per-domain, not more breadth.

| Category | Maturity | One-line reality |
|---|---|---|
| Zero Trust (ZTNA) | ~55% | Access broker + microseg + **real OIDC/JWT on-path** (alg-confusion rejected) + dual-credential logic + agent-signed posture bound to the reporting key. **But the posture chain is INERT in production** — publisher and proxy derive the subject key differently, so every compliant device reads `HasPosture=false` (IDENT-1, the top of the queue). No hardware attestation, no JWKS rotation, no ZTNA client. |
| DLP | ~45% core | Strong sandboxed detection core; enforcement wired behind `OPENSHIELD_ENFORCE`; compliance packs (PCI/HIPAA/GDPR) load and change decisions — **but packs REPLACE the default policy**, so enabling one silently disables HIPS + out-of-scope detectors (DLP-5b). +EIN/NPI/NHS/SIN/ABA/routing/phone detectors. Still one channel, no EDM/OCR/ML. |
| NIPS / NTPS | ~30% | Forward-proxy egress DLP + TLS interception + live **DNS + SMTP listeners wired** with a shared rate-limiter and panic-recover. SMTP body DLP reaches the sandboxed worker. Still no inline/transparent (ADR-8), no signatures/threat-intel (NIPS-2). |
| SIEM | ~35% | `/events` search **mounted + gated**, **materialized incidents** (id/state), cross-host correlation, alert lifecycle+ack, async multi-sink HMAC webhooks, persisted UEBA baselines, case workflow, syslog. Still: no unified alert-lifecycle schema (ADR-10), notify idempotency broken (SIEM-12), no UI, no CEF/WEF. |
| HIPS | ~30% | Phase E **runs end-to-end** — real auditd source → real pid → real KILL, behavioral→decision, detector evasions closed (mutation-confirmed). **KILL safety incomplete**: pid-reuse revalidation ineffective + the critical-process allowlist is self-immunizing (HIPS-7/8). `DENY_EXEC` deliberately deferred (needs `FAN_OPEN_EXEC_PERM`). |
| NAC | 0% | Absent; off-pipeline. **Parked** by owner decision (ADR-0) — tickets staged, off the queue and out of headline claims. |
| VPN | 0% | Absent; off-pipeline. **Parked** by owner decision (ADR-0). |

**Crown jewel (protect it):** the per-agent forward-secure hash-chained ledger + external anchoring
is real end-to-end and is the platform's strongest asset. Do not regress it.

---

## ✅ Done — verified closed (mutation-confirmed on live substrate). Do NOT re-open or re-propose.

Confirmed by mutation-reintroduction on live Postgres/NATS/TLS across Rounds 31–32 — reverting each
guard flips its test to FAIL.

- **Security (Bucket S):** SEC-1 (sign/verify risk+posture channels) · SEC-2 (enrollment can't
  overwrite a key or un-revoke) · SEC-3+SEC-11 (dead-man's-switch & operator views count only
  *verified* telemetry) · SEC-4 (no silent server-side NATS loss — pending-limits + counted error
  handler) · SEC-5 (purge/tombstone honors `legal_holds`) · SEC-6 (non-owner ledger DB role, *wired*
  via PLAT-6b — the append-only boundary now protects the running product) · SEC-7 (no-follow safe
  reader) · SEC-8 (operator-search input validation, 400s + caps) · SEC-9 (access-proxy header
  hygiene + trustworthy identity header) · SEC-10 (persist restart-fragile state; monotonic
  `context_version`) · SEC-12 (posture signature *bound to the reporting agent's key* — the signature
  binding is correct; note the subject-key wiring is still inert in prod, tracked as IDENT-1).
- **Honesty (Bucket H):** HON-1 (worker loads + verifies signed custom rules) · HON-2 (case-open
  places the legal hold SEC-5 consumes) · HON-3 (engine registers enforcers under
  `OPENSHIELD_ENFORCE`; real file moved) · HON-4 (agent-signed device-posture producer).
- **Platform:** PLAT-4/4b (Prometheus metrics, low-cardinality, behind constant-time bearer auth +
  non-loopback bind guard) · PLAT-6b (restricted `openshield_app` role wired across compose/systemd/
  e2e) · PLAT-8 (DSAR / data-subject access request).
- **Zero Trust:** ZT-2 (OIDC/JWT verifier on-path at the access proxy; `alg=none`/HS-confusion
  rejected; iss/aud/exp/nbf enforced) · ZT-3 (dual-credential logic: device cert + user token, posture
  keyed by device — *logic correct, but blocked in prod by IDENT-1*).
- **DLP:** case/incident workflow (DLP-4) · compliance packs load and change a Decision (DLP-5 —
  *composition bug tracked as DLP-5b*) · detector breadth: phone, US EIN/NPI/routing-ABA, Canadian
  SIN, UK NHS (DLP-7 partial) · bare-run detector FP bounds.
- **NIPS:** NIPS-3 (DNS + SMTP parsers wired to live listeners) · SMTP listener hardened (bounded
  reader + deadline + accept semaphore — *test is false-premise, tracked as NIPS-3-SMTP-TEST*) ·
  NIPS-7 (shared `connectors/limiter` rate-limits DNS + syslog before the ledger write) · ENG-1
  (network-content → sandboxed worker classify path) · ENG-2 (parser-panic `recover()` at per-item
  boundaries; D35 in-process deviation documented).
- **SIEM:** SIEM-1 (`/events` search mounted on the served TLS mux, operator-gated) · SIEM-2
  (cross-host `agent_id` from the verified envelope) · SIEM-6 (alert lifecycle: severity + ack behind
  operator mTLS) · SIEM-8 (multi-sink fanout + constant-time HMAC webhook + async off-ingest) ·
  SIEM-11 (materialized incidents with id/state + `NULLIF` host-count) · SIEM-5 (persisted UEBA
  baselines, reload-before-ingest) · SIEM-3/4 (case workflow, syslog ingest).
- **HIPS:** HIPS-5a/b/c (Phase E wired end-to-end: real `execaudit` source → engine extracts
  `ProcessSubject.pid` by event kind → real `KillEnforcer`) · HIPS-6 (detector 1-char bypasses closed:
  encoded-PS prefix match, auditd hex-decode, pipe-to-any-shell) · HIPS-3 (`KILL_PROCESS` typed verb
  landed under the T1 red line; `DENY_EXEC` deliberately deferred).

---

## 🔴 Next — the active queue (in priority order)

Work top to bottom. All unblocked (no owner gate). Each ticket names the ADR it implements where one
applies.

### IDENT-1 · Canonical device identity — fixes the inert posture chain — P0 (HIGH) · gateway+agent+enroll · M
- **Confirmed by three independent agents.** SEC-12's signature binding is correct, but the feature is
  **dead on the real path**: the fleet-agent stores posture under the raw `OPENSHIELD_SUBJECT`
  (default = raw agentID — `cmd/openshield-fleet-agent/main.go:44,133`, stored raw at
  `internal/gateway/posture.go:99`), while the access proxy looks it up under `pseudonym(CN)` =
  `"sub_"+hex(sha256("zt-client-subject:"+CN)[:12])` (`access.go:176`, `identity/identity.go:83`,
  **unexported, unshared**). `rawAgentID ≠ sub_<hash>` → the verified, stored posture is never found →
  `HasPosture=false` → any posture-gated policy denies *every* real compliant device. ZT-3's advertised
  "finance user on a compliant device → 200" is unreachable. Tests pass only because they seed
  `Set(pseudonym(CN))` and read the same literal — the recurring pattern, masking a HIGH prod bug.
- **Fix (ADR-6):** canonicalize on the enrolled agent identity; provision RoleClient certs with
  `CN = agent identity`; export ONE shared pseudonym derivation used by enrollment, the posture
  publisher, AND the access proxy. Re-key the SEC-12 roster/`keyFor` to the canonical pseudonym too.
- **Verify:** an e2e that publishes via the *real* `posture.Publish` and asserts `Get(pseudonym(CN))`
  hits; a compliant device reaches a posture-gated upstream; a non-compliant device is denied.

### DLP-5b · Compose policy packs, don't replace the default — P1 · policy · M
- `NewPack` swaps `default.rego` wholesale (`internal/policy/embed.go`), and the pack files omit the
  HIPS `behavioral_alert` rule and the CPF/card strong-detector alert — so **enabling PCI silently
  turns off behavioral process alerting** (and each pack drops the detectors outside its scope). No
  test asserts the default protections survive pack selection, because they don't.
- **Fix (ADR-5):** compile default + selected packs + operator custom rules under a
  most-restrictive-wins lattice (data-plane verbs only); stamp a bundle id/version on the Decision.
- **Verify:** PCI pack ON still ALERTs on a behavioral hit and a raw CPF; a test proves default
  protections survive every pack.

### SIEM-12 · Real notification idempotency — P2 · notify · S
- The async hand-off is real (`TestEmitDoesNotBlockIngest`), but `newNotifyID()` is `crypto/rand`
  per-emit (`notify.go:59`) and is **never checked server-side**. The scenario it targets — agent
  re-sends telemetry → server re-detects → re-emits — mints a new id each time, so nothing dedupes →
  the double-page persists.
- **Fix:** derive the id deterministically from alert content
  (`hash(kind|subject|agentID|window-bucket)`) + a bounded server-side seen-set checked in `emit`/
  `deliverLoop`. **Verify:** emit the same logical alert twice → exactly one delivery.

### NIPS-3-SMTP-TEST · Make the OOM guard's test real — P2 · connector test · XS
- The bounded reader is correct, but `harden_test.go` streams 64 KiB against the 32 MiB cap, so
  **removing the `io.LimitReader` still ships green** (the idle deadline masks it) — the signature
  false-premise pattern. **Fix:** inject a small `maxBody` + a large idle timeout, stream past the cap
  with no newline, assert `Dropped>0` without the deadline firing. (Test-only; the guard is correct.)

### HIPS-8 · Trusted critical-process identity — KILL containment bypass — P2 · enforcer · M
- The safety allowlist keys on kernel `comm`, which a process sets for itself
  (`prctl(PR_SET_NAME)`/argv[0]) — `internal/enforcers/process/process.go:29-43`. Malware that names
  itself `sshd`/`systemd`/`openshield*` becomes **permanently unkillable** by HIPS; it opts *into*
  immunity. Worse than a renamed-LOLBin detection evasion — this grants immunity from *containment*.
- **Fix:** gate the allowlist on a trusted identity — cgroup/systemd unit, binary hash, or a
  known-platform pid-set — not self-reported `comm`. **Verify:** a process that renames itself `sshd`
  but is not the real unit is still killed.

### HIPS-7 · pid-reuse revalidation (reopen) — P2 · enforcer · M
- Critical-allowlist and argc bound are real (mutation-confirmed). But the pid-reuse guard does nothing:
  `platformKill` calls `PidfdOpen(pid)` **at kill time** (`kill_linux.go:17`), and the event carries
  only `Pid int32` — no pidfd/start-time captured at observation. On a recycled pid it opens and kills
  the **new** holder — exactly what the commit claims to prevent. No test drives the real syscall path.
- **Fix:** capture a pidfd (or `/proc/<pid>/stat` starttime) in the exec source when the
  `ProcessSubject` is built, carry it on the event, revalidate/send via that captured fd in
  `EnforceTarget`. **Verify:** a decide→recycle→kill test proves the new holder is spared.

### SIEM-8b · Webhook replay protection — P2 · notify · S
- The MAC covers the body only (no timestamp/nonce) and one secret is shared across sinks → a captured
  `(body, sig)` validates forever at any sink. **Fix:** sign `"t=<unix>." + body`, send `t` in a
  header, receiver rejects stale. (Optionally per-sink secrets.)

### SIEM-5b · Prune + validate UEBA baselines — P2 · analytics · S
- No TTL/prune (O(N) UPSERTs forever, unbounded row + map growth); load accepts a NaN/negative `count`
  or future `last_seen` (decay > 1 inflates the baseline; reachable only with DB write access).
  **Fix:** prune decayed-below-ε rows + batch the upsert in a txn; validate on load; persist the
  `peerLastAlert` cooldown.

### SIEM-6b · Unified alert/incident lifecycle schema — P2 · schema · M — implements ADR-10
- `peer_alerts` already carries `agent_id` (mig 015) and ack columns (016); still missing as
  first-class columns: **severity, a dedup/correlation key, and a status lifecycle beyond ack**
  (open→triaged→closed). One migration adds them **before any further SIEM detection ships**, so each
  new detector writes the lifecycle fields from day one. (Do NOT re-add `agent_id`/ack.)

### PLAT-3 (RBAC) · Per-route analyst RBAC tiers — P1 · authz · M — implements ADR-4
- Add read-only-analyst / responder / admin tiers on the existing `requireRole` seam, optionally
  OIDC-group-backed (ZT-2 gives a real verifier). Defer org multi-tenancy (XL). Unblocks the PLAT-1 UI,
  which needs its authz model fixed before design.

### Then — the platform-durability & deepening lane (in this order)
1. **PLAT-2 · JetStream telemetry durability** (ADR-2) — durable consumers with ack; replace the
   per-message `FOR UPDATE` in `VerifySigned` with a per-agent advisory lock / batched verify. Closes
   SEC-4's root. Prerequisite for any HA work.
2. **PLAT-2b · Active-passive HA** (ADR-3) — Postgres leader lease + Postgres HA + JetStream. Decide
   before more in-memory state accretes.
3. **ZT-2b · Live JWKS refresher** (ADR-7) → **ZT-1 · Hardware attestation** — do ZT-1 *after* IDENT-1
   fixes the identity it binds to.
4. **NIPS-1 · TPROXY inline connector** (ADR-8) **with NIPS-2 · signatures/threat-intel** — sequence
   together; without signatures it is not an IPS.
5. **DLP-3 · server-side EDM/OCR** (ADR-9) + **DLP-2 · exfil-channel producers**.
- **Cross-platform (PLAT-7)** runs in parallel throughout (ADR-11): owner drives cert/entitlement
  procurement; builder lands GOOS skeletons + Windows observation producers now.

### Minor (fold into the owning ticket, no separate proposal)
`/incidents?limit=` still silently defaults instead of 400ing (finish the SEC-8 rule on that param) ·
PLAT-4b `main.go` metrics *wiring* has no test (guard tested in isolation) · `EnsureAppLogin`'s
existing-role branch should re-assert `NOSUPERUSER NOCREATEROLE` · SMTP `handle`/`processOne` recover
present but not individually tested · SIEM-8c (per-sink fanout goroutine, P3) · ZT-2 residuals (clock-
skew leeway on exp/nbf; bearer tokens replayable until exp and not device-bound — jti/DPoP, P2).

---

## Architecture decisions (Round-32) — the closed forks

> The owner asked to "close missing architectural decisions to move forward." These ADRs resolve the
> forks the audit surfaced so the builder has an unambiguous runway. **ADR-0/-11 are owner decisions;
> ADR-2…-10 are technical decisions made to unblock — the owner may override any.** Each names the
> ticket(s) that implement it. The frozen-core discipline (D26/D69) still governs.

**ADR-0 · NAC and VPN are PARKED (owner decision, 2026-07-22).** They do not fit the pipeline (no
Event, no Decision; the access proxy is L7-HTTP-only, categorically not a VPN). Decision: **keep them
off the builder's queue and out of the headline category claims for now, with `NAC-*`/`VPN-*` staged**
so either can be green-lit later without another audit. If green-lit, they are separately-scoped
off-pipeline products that reuse the PKI/identity and *feed* posture/risk in — not pipeline plugins.

**ADR-2 · Telemetry durability = NATS JetStream (implements PLAT-2, closes SEC-4's root).** Core NATS
is at-most-once; loss is *detected* (sequence gaps) but unrecoverable, and the agent spool only covers
broker-unreachable. Decision: **durable JetStream consumers with explicit ack** for telemetry ingest;
keep the spool as the pre-broker buffer. Pair with replacing the per-message `FOR UPDATE` in
`VerifySigned` (hard-serializes ingest) with a per-agent advisory lock or batched verify. Prerequisite
for HA/scale. (Honors D12: JetStream is a **bus** for delivery durability, NOT the system-of-record —
the hash-chained ledger remains the evidence store; do not use stream retention as evidence.)

**ADR-3 · HA topology = active-passive first (implements PLAT-2b).** Single server holds in-memory
state (UEBA analyzer, notify dedup set, alert cooldowns); SIEM-5 made baselines durable but **not
multi-writer-safe**. Decision: **active-passive via a Postgres leader lease + Postgres HA +
JetStream**; defer stateless-horizontal. Decide now, before more in-memory state accretes.

**ADR-4 · Authz = per-route RBAC tiers now, org multi-tenancy deferred (implements PLAT-3).** Today
there are two cert-OU roles (agent/operator). Decision: **add analyst/responder/admin tiers on the
existing `requireRole` seam**, optionally OIDC-group-backed; **defer org tenancy** (XL) until demand.
Unblocks the PLAT-1 UI.

**ADR-5 · Policy = compose, most-restrictive-wins (implements DLP-5b).** `policy.New` takes one module
and packs *replace* the default — dropping protections. Decision: **compile default + selected packs +
operator custom rules together**, stamp a bundle id/version on every Decision. The combine rule is a
most-restrictive-wins lattice **scoped to the data-plane verbs that can compete for the same data
event**: `ALLOW < ALERT < REDIRECT < ENCRYPT_LOCAL < QUARANTINE_LOCAL < BLOCK` (tiebreak: QUARANTINE
outranks ENCRYPT). **The process-control verbs `DENY_EXEC`/`KILL_PROCESS` are NOT in this lattice and
MUST NOT be reachable by pack composition** — they are decided on a separate axis by the behavioral
rule over *process* events, so a DLP/compliance pack can never silently escalate to killing a process.
Modules emitting a process verb and modules emitting a data verb never combine (different event kinds).

**ADR-6 · One canonical device identity (implements IDENT-1).** Three parties key differently today
(enrollment, posture publisher via `OPENSHIELD_SUBJECT`, access proxy via `pseudonym(CN)`); ZT-1 would
add a fourth. Decision: **canonicalize on the enrolled agent identity; provision RoleClient certs with
`CN = agent identity`; export ONE shared pseudonym derivation** imported by enrollment, the posture
publisher, and the access proxy (re-key the SEC-12 roster too). Must land *before* ZT-1 — attestation
binds to whatever identity is chosen; this is the ZTNA-vs-toy line. (`provision.NewClientCert` already
takes an arbitrary CN; D23 pseudonymization is preserved — derivation shared, not removed.)

**ADR-7 · Live JWKS via a background refresher (implements ZT-2b).** Static PEM keys mean IdP rotation
= restart. Decision: **a background JWKS refresher that serves-stale-on-fetch-failure, refreshes
rate-limited on a `kid` miss, and NEVER fetches on the request path.** Unblocks Okta/Entra.

**ADR-8 · NIPS inline = opt-in TPROXY, not L2 bridge (guides NIPS-1).** DNS is already tap/mirror-only
(DEPLOY-1). For transparent HTTP: **TPROXY/nftables redirect as an opt-in deploy mode with a bypass
watchdog; reject L2 bridging.** External-gated (root/`CAP_NET_ADMIN`) — confirm empirically. The
deliberate D73/D17 egress fail-open MUST survive: inline **fails-to-wire, never fails-closed-the-
network.** Sequence **NIPS-2 signatures *with* NIPS-1**.

**ADR-9 · EDM/OCR placement = server-side first, then a signed index into the sandbox (guides DLP-3).**
D10/D11 forbid content or fingerprints leaving the endpoint. Decision: **server-side EDM/OCR for
gateway-visible flows first** (content already transits the gateway's sandbox); for endpoints, **ship
a signed, bloom/k-anonymized EDM index *down* into the sandboxed classify worker** — content and hashes
still never leave. Never upload endpoint content or fingerprints.

**ADR-10 · Unified alert/incident lifecycle schema now (implements SIEM-6b).** One migration adds
severity/dedup-key/status-lifecycle to `peer_alerts` before further SIEM detection ships. (`agent_id`
and ack already shipped in migrations 015/016 — verify at HEAD; do not re-add.)

**ADR-11 · Cross-platform = owner starts procurement, builder does observation now (owner decision,
2026-07-22, implements PLAT-7).** Enforcement is externally gated (Windows EV cert + attested
minifilter; macOS Endpoint Security entitlement — long-lead owner actions). Decision: **owner kicks off
cert/entitlement acquisition now; in parallel the builder lands GOOS build-tag skeletons and Windows
user-mode *observation* producers (clipboard/print) that need no attestation.** Gating limits
enforcement, not observation; most enterprise data lives on Windows. (T1 `DENY_EXEC` still needs its
per-verb owner sign-off before wiring; T2 risk-loop and T1 `KILL_PROCESS` are resolved in code.)

---

## Backlog by category (after the queue)

Deeper feature work that extends the Phases (A–F, see *Reference*). Pull only after the queue.
Pipeline fit noted `P/C/X/A/D` = producer/classify/context/action/data-plane, or off-pipeline.

### Zero Trust / ZTNA
- **ZT-1 · Hardware device-posture attestation** — P1 · X + producer · XL. Posture is self-reported
  booleans; a compromised-but-alive agent signs `Compliant=true`. Add TPM/measured-boot signed quotes
  verified at the gateway (`google/go-tpm` is `// indirect` today — greenfield). **Must follow IDENT-1
  (ADR-6).** The ZTNA-vs-toy line.
- **ZT-4 · ZTNA client/connector model** — P2 · new work · L. Enterprise ZTNA is agent-brokered; today
  it is server-side reverse-proxy only.
- **ZT-5 · Policy admin + session recording** — P2 · new work · L. Policy is a boot-loaded file; add an
  admin surface (ties to PLAT-1) + per-session audit.
- **ZT-6 · SAML** — P3 · producer · L. Only after OIDC proves the SSO seam.

### DLP
- **DLP-2 · Real exfiltration-channel producers** — P0-for-product · producers (+ maybe actions) · XL,
  per-OS. Clipboard, print, screenshot, removable-media file-copy (content-aware), cloud-sync/CASB. A
  DLP that watches directories but not the channels users exfiltrate through is not a DLP.
- **DLP-3 · EDM / IDM / OCR** — P1 · classify (server-side) · XL. Exact-data-match, doc fingerprinting,
  OCR. **Placement fixed by ADR-9** — server-side / signed index into the sandbox; never break D10/D11.
- **DLP-6 · Endpoint user coaching/justification** — P1 · X + UI · M. REDIRECT-to-coaching exists at
  the network gateway only; bring it to the endpoint.
- **DLP-7 · Detection breadth (remainder)** — P1 · classify · M–L. Passport / national-ID beyond the
  landed set, driver's license, keyword-proximity/context rules. Ships via the signed custom-rule
  surface + built-ins.
- **DLP-8 · Format depth** — P2 · classify · M. Nested-archive recursion (stops at one level today),
  RTF / legacy `.doc`, response-body multipart/gzip (shared with NIPS-4).

### NIPS / NTPS
- **NIPS-1 · Transparent/inline connector** — P0 · data-plane (D) · L. **Approach fixed by ADR-8**
  (opt-in TPROXY, bypass watchdog, preserve egress fail-open).
- **NIPS-2 · Signature / threat-intel engine** — P0 · classify (C) · L. Suricata/Snort-ruleset or
  YARA-style network classifier + IOC feeds. Without this it is categorically not an IPS. **Sequence
  with NIPS-1.**
- **NIPS-4 · Response-body inspection** — P1 · classify · M. Today only the *request* body is
  classified; the response is copied through. Add buffered/streamed classification with memory bounds,
  gzip + multipart decode (shared with DLP-8). **Must preserve the deliberate D73/D17 egress fail-open.**
- **NIPS-5 · HTTP/2 & QUIC interception** — P2 · new work · L. HTTP/1.1 only today.
- **NIPS-6 · Raw TCP/L4 metadata connector + anomaly/beaconing detection** — P2 · P + C · L.

### SIEM
- **SIEM-4 · External log ingestion beyond syslog** — P1 · connector class · M. CEF / WEF / cloud-JSON
  formats; wire ingested logs into the *verified* ingest + search/correlation path (not just a
  listener). Syslog precedent landed.
- **SIEM-7 · MITRE ATT&CK mapping** — P1 · classify metadata · M. Tag detections with techniques.
- **SIEM-9 · Threat-intel enrichment + saved searches / scheduled reports** — P2 · S–M / M.
- **SIEM-10 · Compliance/retention reporting** — P2 · M. What was purged, when, by which policy (ties
  to PLAT-8).
- *(SIEM event-search deepening: `fleet_telemetry` payloads are still opaque proto `BYTEA`; typed/JSONB
  columns at ingest would enable field-level hunting — larger surface, pull after the queue.)*

### HIPS (endpoint-behavioral domain — Phase E, landed and hardening)
- **HIPS-3 (remainder) · `DENY_EXEC`** — P0 · action expansion (A, T1) · L. True inline deny needs
  `FAN_OPEN_EXEC_PERM` + per-verb owner sign-off on T1. `KILL_PROCESS` already landed.
- **HIPS-4 · FIM, memory/injection detection, ransomware canary, application whitelisting** — each a
  separate subsystem-sized bet · XL each. Do not bundle.

### Platform (remainder, not in the immediate queue)
- **PLAT-5 · Config management beyond env vars** — P2 · S–M. Typed config (file + env override),
  validated fail-fast at boot; secrets as file paths.
- **PLAT-6 · Release, packaging & deploy** — P2 · M. Tagged releases + reproducible signed binaries
  (goreleaser), container/systemd/Helm deploy path. Keep the open-core boundary intact.

---

## Parked (owner-gated — do not start)

- **PLAT-1 · A UI** — P1 · XL — *the single biggest enterprise-credibility gap.* Minimal SPA (or rich
  TUI first) over the operator-read API: fleet health, alerts, incidents, search, agent status, cases.
  Needs a frontend-toolchain decision (repo is pure Go). Owner-reserved (explicitly last). Its authz
  model is unblocked by ADR-4 (PLAT-3).
- **NAC** (off-pipeline, parked — ADR-0): NAC-1 (802.1X/RADIUS authenticator + switch/AP integration) ·
  NAC-2 (posture-gated admission + quarantine VLAN) · NAC-3 (guest onboarding / captive portal /
  agentless discovery). All XL, network-infrastructure, not pipeline plugins.
- **VPN** (off-pipeline, parked — ADR-0): VPN-1 (WireGuard/IPsec/TLS tunnel data plane + client, XL) ·
  VPN-2 (split-tunnel policy + per-tunnel cert lifecycle, L). ZTNA is not a VPN.

---

## Reference — design rationale (rarely changes)

### The lens: does it fit the frozen pipeline?

The bet is a fixed pipeline — **Event → Classify → Policy → Decision → Enforce → Audit** — that
absorbs capabilities as plugins, proven data-plane-agnostic three times (endpoint files D48, peer-UEBA
D53, network gateway D69). Every piece is classified by how it meets that pipeline:

- **P — Producer plugin.** A new Event source (a connector). Additive; the D69 seam holds.
- **C — Classify plugin.** A new detector/analyzer in the sandboxed worker. Additive.
- **X — Context input.** A new typed Policy input via the `ResolveContext`/`State.Context` seam
  (D28/D53). Additive — this is the seam identity and risk flow through.
- **A — Action expansion.** A new verb in the **closed** `Action` set (D14). NOT additive in spirit —
  the closed set is a security feature (a compromised control plane cannot express "upload to URL").
  Each new action is a deliberate, typed, single-purpose expansion, decided one at a time.
- **D — New data-plane shape.** A new connector topology (transparent/inline vs forward-proxy). The
  pipeline is unchanged; the connector is new.
- **E — External gating.** Not a design problem (certs, entitlements, ecosystem).

The recurring discipline: **the core stays frozen; capability lands in producers, classify plugins,
typed context, and — rarely and deliberately — one new action at a time.**

### What stays frozen

The core does not change: `core.Dispatcher`, `State`, `Stage`, `Registry`, the
`Enforcer`/`TargetedEnforcer` interfaces, `OnOutcome`, the ledger, the boundary rule (D10/D29 — content
stays in the classifying process; only type+count+metadata cross). If any work forces a core change,
that is the signal to stop and re-examine — the D26/D69 fitness tests apply.

### The four tensions (T1–T4) — status

- **T1 — Does the closed action set (D14) expand?** *Resolved: expand one typed verb per capability,
  never a parameterised framework.* `KILL_PROCESS` landed as a bounded verb; `DENY_EXEC` still needs
  per-verb owner sign-off before wiring.
- **T2 — Does risk flow back to enforcement (the D54 dead-end)?** *Resolved in code: the server
  computes+publishes risk; the endpoint/gateway reads it as typed Policy context (D28) and decides
  locally.* The server informs; it never actuates (D14 preserved).
- **T3 — One product or a platform (DLP → XDR)?** *Resolved: the platform bet is made — OpenShield is
  an XDR.* Detection-and-response now spans **endpoint** (file DLP + HIPS behavioral/KILL), **network**
  (forward-proxy + DNS/SMTP NDR), and **identity** (ZTNA/OIDC), correlated server-side (SIEM
  incidents/UEBA + the ledger) on one pipeline. **DLP is one classify-domain, not the whole product.**
  The discipline shifts from "don't go broad" to **"keep each domain credible — depth beats shallow
  breadth"**: the domains sit at 30–55% today (see the status table), so the standing risk is now
  half-built breadth, not scope creep. New domains still enter as explicit, separately-scoped bets
  (a producer + a classify-domain + at most one deliberate action), never a core change.
- **T4 — Categories that do NOT fit the pipeline (NAC/VPN).** *Resolved by the owner: PARKED (ADR-0)* —
  they produce no Event and consume no Decision. Off the queue, out of headline claims, tickets staged.

### Phased plan (original design sequence, for context)

Ordered by leverage-per-architectural-risk; much of A/C/E/F has since landed (see Done/queue).

- **Phase A — Identity & Zero-Trust foundation (X + P + one A).** Identity producer at the proxy
  (verified pseudonymised subject replacing `sha256(src-IP)`); identity+posture as typed Policy context
  (D28/D53); close the risk loop (T2). *Largely landed; IDENT-1 + ZT-1 remain.*
- **Phase B — Inline prevention (enforcement-timing, one A).** Two-tier classify in the fanotify
  permission window (fast pre-filter + async full); wire the privileged permission-mode agent (D18/D62)
  under fail-open; `BLOCK` truly inline for files. *Open — the DLP credibility gap.*
- **Phase C — Network breadth & transparent inline (P + D + C).** Transparent/inline connector (ADR-8);
  non-HTTP producers (DNS/SMTP *landed*; raw TCP/L4 open); response-body + multipart + decompression;
  IDS-signature classify plugin (NIPS-2).
- **Phase D — Detection depth (C).** Document-structure parsing (PDF landed); secrets/health/national-ID
  detectors (largely landed); admin-authorable signed detectors (landed); optional ML/EDM (ADR-9).
- **Phase E — HIPS (P + a bounded A + C) — the endpoint-behavioral domain (the platform bet, now
  taken).** Exec producer + behavioral classifier +
  `KILL_PROCESS`/`DENY_EXEC`. *Runs end-to-end; hardening in the queue (HIPS-7/8), `DENY_EXEC` deferred.*
- **Phase F — SIEM/analytics depth (server-side).** Search API (landed), correlation/rules (landed),
  case workflow (landed), dashboards/UI (PLAT-1, parked), third-party log ingest (syslog landed;
  CEF/WEF = SIEM-4).
- **Cross-platform (Windows/macOS) — parallel, external-gated (E).** Portable all-Go core; per-OS
  producers/enforcers. *Owner drives procurement, builder does observation now — ADR-11.*

---

## Audit history

Round-by-round detail lives in git history and the session memory; each round's residuals were folded
into the Done list and the queue above.

- **Round-30 (2026-07-21)** — first full 7-category enterprise audit. Produced the original
  SEC-/HON-/PLAT- buckets + the category feature backlog. Caught its own same-day staleness against a
  concurrent builder (→ the re-verify-at-HEAD discipline).
- **Round-31 (through D136)** — mutation-verified the Bucket S/H fixes on live substrate; caught the
  unmounted `/events`, the HIPS scaffolding-not-runnable state, and the SMTP/ENG residuals.
- **Round-32 (through D168, this file)** — verified the entire R31 queue + the net-new ZT/DLP/SIEM
  features closed; surfaced IDENT-1 (HIGH, inert posture chain), the DLP-5b policy-replace bug, and the
  HIPS-7/8 KILL-safety gaps; closed the 11 open architecture forks as ADR-0…ADR-11. Independently
  double-checked (all findings confirmed; two ADR text errors fixed pre-commit).
