# OpenShield — Round-1 Adversarial Review

**Date:** 2026-07-20 · **Inputs:** intake.md, reports/scouting-r1.md
**Reviewers (4, independent, instructed to attack not praise):** senior architecture ·
applied cryptography · red team / threat model · privacy law + OSS sustainability

No code exists. This reviews the *decisions* (D1-D9) and the brief's stated principles.

---

## Verdict

The pipeline architecture largely survives. **The brief's stated principles do not.** Three of
the four reviewers independently concluded that OpenShield currently promises properties it
cannot deliver — in privacy, in tamper-proofing, and in prevention. None of these are
implementation bugs; all are claims that must be reworded before they mislead a deployer who
bets real data on them.

Nothing here kills the project. Several things kill specific *sentences* in the brief.

---

## The big four

### B1 — "Store hashes, not content" is not a privacy control for the data this product targets

Hashing protects high-entropy secrets. The identifiers this product exists to find are
low-entropy and structured, so a hash is an index into a precomputable table, not a shield:

| Identifier | Keyspace | Notes |
|---|---|---|
| SSN | 10^9 | Full rainbow table in hours on a laptop |
| Credit card | ~10^7 effective | BIN is public; Luhn removes ~90% of the space; most cracks < 2 min |
| **CPF (Brazil)** | ~10^9 | Last 2 of 11 digits are a checksum → same class as SSN |
| Phone (known area) | 10^7-10^8 | |
| DOB | ~36,500 | Trivial |

**Salting does not fix it.** It prevents cross-deployment table reuse; it does nothing once the
salt is known. And the architecture makes this worse: cross-endpoint matching requires a
*deterministic* key, but classification happens *on the endpoint*, so the matching key must
live on every agent — precisely where root compromise is most likely.

**Fix:** do not exact-match-hash low-entropy fields at all. Detect by format + checksum
(regex + Luhn/CPF digit validation) locally, and transmit only **type + confidence + count**.
Reserve keyed HMAC/EDM matching for high-entropy composite records, with the key server-side
only, never distributed to agents in reusable form.

### B2 — Embeddings and fuzzy fingerprints are content, not a de-identification layer

Similarity-preserving hashes (ssdeep/TLSH/simhash/MinHash) preserve content structure by
design — that is the feature and the leak. Dense embeddings are invertible: vec2text recovers
**92% of 32-token inputs exactly**, including names from clinical notes (arXiv:2310.06816).

**Shipping embeddings off-endpoint is not meaningfully more private than shipping the text.**
Treat embeddings and fuzzy fingerprints as regulated content — encrypted, access-controlled,
and **never distributed through the community Hub**.

### B3 — "Tamper-proof audit log" is not achievable in a single self-hosted trust domain

A log signed by the same root process that writes it proves nothing about tampering by that
process. Hash chains detect linear edits; a full rewrite is available to whoever holds the key,
which on a single node is the host under attack.

Achievable offline is **forward-integrity**, not tamper-proofing: key-evolving schemes
(Schneier-Kelsey; Ma-Tsudik forward-secure sequential aggregate signatures) so an attacker who
compromises the agent *now* cannot alter entries from *before* compromise. They can still
suppress or fabricate going forward, or destroy the log outright. Crosby-Wallach history trees
are the right underlying structure.

**Fix:** implement forward-integrity locally; periodically anchor the Merkle root to a separate
trust domain (another machine, WORM/object-lock storage, or a public transparency service when
online). Claim: *"tamper-evident with forward-integrity between anchors; full tamper-proofing
requires an external witness outside the deployer's control."* A legal chain-of-custody claim
needs that anchor — without it, do not use the phrase.

### B4 — Against a user with root on their own machine, a host agent is defeated

`systemctl stop`/`mask`, live USB, mount the disk elsewhere, exfil from a VM, block egress so
nothing syncs, LD_PRELOAD, or a phone camera pointed at the screen. None have a technical fix
that doesn't require distrusting the OS the agent runs on.

The honest goal is **tamper-detection**, not prevention: heartbeat/dead-man's-switch,
"agent last seen" per host, and an audit event the moment the unit stops.

**This directly affects the dogfood plan:** the owner has root on his own fleet, so dogfooding
is case (c). It validates the pipeline, classifier, plumbing and operability bar — it *cannot*
validate the product as a control, because the owner can trivially defeat it. Know this before
it feels like failure.

| Adversary | Stoppable by host agent? |
|---|---|
| Careless insider, no intent | **Yes** — the design centre |
| Malicious insider, no local admin | **Partially** — covered hooks only |
| Malicious insider **with root** | **No** |
| External attacker who owns the host | **No** |

---

## Convergent findings (multiple independent reviewers)

### C1 — The agent makes the machine less secure unless privilege-split (crypto + red team)

Root + `CAP_SYS_ADMIN` + parsing attacker-controlled PDFs/archives/images is the textbook
recipe for turning a memory bug into host compromise. Precedent is a repeat offender: ClamAV's
**CVE-2025-20260** (PDF parser heap overflow → RCE), plus a long history in Defender and Sophos.

**Mandatory, not optional:**
- All untrusted parsing runs in a **separate unprivileged, seccomp-confined, network-less
  worker** with cgroup limits, returning only structured verdicts.
- The process holding `CAP_SYS_ADMIN` **never decodes attacker-controlled bytes.**
- Decompression-bomb limits (max ratio, expanded size, nesting depth) before any parser runs.
- Privilege-split the agent: small privileged helper for fanotify; de-privileged main process.

### C2 — Hub content-hash trust is insufficient; this is fleet-wide root-equivalent (crypto + red team)

CrowdSec's model (content hash vs a centrally served index over HTTPS) answers "did I download
what the index said" — not "who may publish." No non-repudiation, no defence against a
compromised maintainer account. Since packs execute at high privilege on every endpoint, this
is a **fleet-wide remote-root-equivalent supply chain** risk.

TUF gives role separation and threshold signing but needs periodic connectivity for
timestamp/snapshot freshness (air-gap breaks the freeze/rollback guarantee). Sigstore keyless
is explicitly broken offline (cosign #3437). **Recommendation:** ed25519 detached signatures
(minisign-style) with maintainer keys pinned at install, TUF-style delegation as authors grow,
metadata cached with expiry and **fail-closed when stale**. **Offline revocation is
fundamentally unsolved** — the propagation window equals the sync interval. Document it; do
not imply it is solved. Until per-author signing exists, the Hub UI must not say "verified" or
"trusted".

### C3 — The brief overclaims; the README must not (all four reviewers, different angles)

Converging on one theme: claim visibility, friction for careless insiders, and a tamper-evident
trail. Do **not** claim prevention of exfiltration, tamper-proofing, or efficacy against
motivated actors. The first researcher who runs `systemctl stop` will publicly disprove
anything stronger. Compete on being open, self-hostable and honest about limits.

---

## Architecture findings

### A1 — The "zero core diffs" fitness test measures the wrong axis

An S3 connector is structurally isomorphic to what exists (another resource-created event). It
passes whether or not the architecture is sound. It is also trivially gamed: type core
interfaces as `map[string]any` so nothing is ever a diff, or reach around the bus into shared
tables. **Keep it, but add a *hard* case — something stateful or catalog-shaped — before
declaring the abstraction validated.**

### A2 — Where the pipeline genuinely leaks

- **UEBA / Insider Risk** need persisted per-entity baselines, not per-event verdicts. Worse:
  meaningful baselining wants *cross-endpoint* comparison, which the "server coordinates,
  doesn't compute" principle forbids. **Decide this now, not on discovery.**
- **Data Discovery** is a scan producing a standing queryable catalog — new core state, not a
  plugin. Synthetic `FileDiscovered` events don't give it a home.
- **Lineage** needs an accumulated graph queried by traversal — a different shape from the
  linear Investigation timeline.
- **"Analytics"** is asserted in the frozen pipeline and never defined. Sketch it or exclude it
  from the freeze claim.

**Fix:** state explicitly that Classification may be stateful, and that Investigation/Analytics
will need graph and catalog subsystems. Do not sell "zero core diffs" as covering capability
classes it has never been tested against.

### A3 — D8 (all-Go) should be scoped, not blanket

Go is right for backend and policy engine — that is where the parity win is real. It is
challenged for the **fanotify permission-response hot path**, where GC pauses and scheduler
jitter sit inside a live permission window, and where the failure mode is the worst one already
identified (a stalled responder parks the machine). "Reviewable by a non-coder" also fails
there: the bugs that matter are watchdog races and fd/handle lifetime, not readable prose.
Unverified: whether Go's `x/sys/unix` fanotify coverage suffices, or whether CGO becomes
necessary — if it does, the parity problem reappears *inside one binary*.

**Fix:** scope D8 to backend + non-hot-path agent code. **Run a GC-pause-under-load spike
before locking Go for the responder**; keep Rust on the table for that one component.

### A4 — Enforcer action set must be closed and typed

"Server coordinates, does not control" is not self-enforcing. A compromised control plane could
push a policy whose action is "upload file to URL," indistinguishable from normal telemetry.
The Enforcer interface needs a **closed, fixed set of action types** (Block / Alert /
Quarantine-local / Encrypt-local), never an open action framework. This is architectural, and
cheap now.

### A5 — Audit storage is undecided and shouldn't be

NATS JetStream is transport with bounded retention, not a tamper-evident system of record.
**Make Postgres the hash-chained audit ledger; JetStream stays a bus.** Name it as a decision.

### A6 — Other gaps

- **Decision contract** is being frozen against block/allow only. Sketch it against
  Insider-Risk/Discovery verbs (alert/ticket/quarantine) or it breaks when the interesting
  roadmap arrives.
- **Missing Context/Enrichment abstraction** — local policy needs asset tier, exception groups,
  org unit. Where does that come from, and how does it stay fresh without violating local
  evaluation? Undesigned.
- **Agent enrollment / first credential** — single-use short-TTL enrollment token or
  TOFU-with-admin-approval. **Never a shared fleet secret.** Per-agent revocable identity;
  telemetry individually signed with sequence numbers (it is evidentiary — same integrity bar
  as the audit log).
- **"Encrypt" enforcement key management** is unspecified: endpoint-only means unrecoverable
  data on device loss (self-inflicted ransomware); escrowed means the control plane becomes a
  KMS needing envelope encryption and audited decrypts.

### A7 — Fail-open is a sanctioned bypass

Correct for stability, but an attacker who makes classification slow (huge file, zip bomb,
ReDoS, load) converts every Block into an Allow — the starvation trick used against WAFs.
**Fix:** fail-open/closed becomes **per-policy, per-action**; every timeout-allow emits a
high-severity audit event (never silence); scan budgets capped (max bytes, backtracking budget,
per-process circuit breaker); timeout *rate* tracked as its own signal.

### A8 — The USB enforcer does not validate the risky part

USB is attach-time allow/deny with no in-kernel blocked process — no timeout, watchdog or
fail-open race. It validates plugin *shape*, not the blocking contract. **Phase 1 should build
and exercise the fail-open timeout watchdog itself** (inject delay, assert auto-`FAN_ALLOW`
fires) while real verdicts stay "always allow."

---

## Legal / sustainability findings

### L1 — Privacy law converts into product requirements (not footnotes)

DPIA is effectively mandatory for this class of monitoring (GDPR Art. 35). Consent is not a
valid basis (EDPB 05/2020 — power imbalance); legitimate interest requires a documented
necessity/proportionality test *before* deployment. Enforcement is live: €32M Amazon France,
€35M H&M, both employee monitoring. **German works councils hold an absolute veto**
(BetrVG §87(1)(6)) — not consultation — over monitoring tools; similar in NL/AT/FR.

**Required product features:**
- Enforced retention limits per category with automatic purge
- Purpose tagging at schema level
- Employee-visible notice mechanism
- Audit trail of **who viewed an investigation**, not only who acted
- Four-eyes principle before HR-visible outcomes
- **Exclusion lists** (personal folders, break time) as a first-class policy primitive
- Pseudonymisation by default; de-anonymise only on documented cause
- **Ship a DPIA template** — turns every deployer's burden into a differentiator

### L2 — Brazil (owner's jurisdiction)

LGPD + CLT + Constitution apply cumulatively. Monitoring corporate equipment is permitted under
*poder diretivo*, but **prior notice** of purpose and retention is required — secret monitoring
is not defensible. Personal devices and off-hours are prohibited.

**Liability:** the **deployer** is the controller and bears essentially all regulatory/civil
exposure. As *author*, the owner has no direct controller liability. Apache-2.0 §7 disclaims
warranty — state this explicitly in project docs, since it is the first question an adopter asks.

### L3 — AI-authored code vs the licence rationale

Apache-2.0 was chosen for its patent grant. But AI-generated code may not be copyrightable in
several jurisdictions absent human authorship — and a work without copyright has nothing for a
licence to attach to. **This was not considered when the licence was chosen.** Practical
posture (OpenJS direction): the human signs commits and takes responsibility, AI authorship is
disclosed via commit trailers, and no personal authorship is claimed that cannot be backed.
Disclose in CONTRIBUTING.md so contributors calibrate.

### L4 — Solo maintainer of a security tool

Donations don't fund kernel-churn tracking or CVE triage — rule out as primary model. Open-core
(Wazuh Inc.) is the only model with precedent at this scale. Foundation is a destination, not a
start. **Recommendation:** keep it a portfolio/dogfood project and defer the sustainability
decision explicitly — but **design for open-core optionality now** (keep managed Hub,
compliance packs and multi-tenant control plane cleanly separable); retrofitting that split is
expensive.

**Day one:** SECURITY.md with an SLA actually meetable solo ("acknowledgment within 5 business
days, no fix-time guarantee"). An honest slow SLA beats an aspirational missed one. Don't
self-appoint as a CNA; use Red Hat's Open Source Root CNA when there are real deployments.

### L5 — Dual-use, consciously

Apache-2.0 has no field-of-use restriction, so nothing prevents abusive-employer or state
surveillance use. "Ethical source" licences (Hippocratic) are **not OSI-approved** and would
contradict the "fully open source" goal. The permissive call is already made — but make it
*consciously* and say so (ETHICS.md sets expectations without legal force).

---

## Proposed new decisions

| # | Decision |
|---|---|
| D10 | No exact-match hashing of low-entropy PII. Format+checksum detection locally; transmit type+confidence+count only. Keyed EDM for high-entropy records, key server-side only. |
| D11 | Embeddings/fuzzy fingerprints = content-equivalent. Encrypted, access-controlled, never in the Hub. |
| D12 | Audit log = forward-integrity + external anchoring. Claim "tamper-evident", never "tamper-proof". Postgres hash-chain; JetStream is bus only. |
| D13 | Privilege-split agent; all untrusted parsing in an unprivileged seccomp/cgroup-confined worker. Decompression-bomb limits. |
| D14 | Enforcer action set is **closed and typed**. |
| D15 | Hub uses ed25519 per-author signing, pinned keys, fail-closed on stale metadata. Offline revocation documented as unsolved. |
| D16 | Tamper-**detection** (heartbeat/dead-man's-switch), never tamper-prevention. |
| D17 | Fail-open is per-policy; every timeout-allow is a loud audit event; scan budgets capped. |
| D18 | Phase 1 exercises the fail-open watchdog for real (injected delay), verdicts still always-allow. |
| D19 | D8 scoped: Go for backend + non-hot-path. GC-pause spike before locking Go for the fanotify responder. |
| D20 | Privacy-law features (L1 list) are Phase-1 architecture, not later additions. |
| D21 | Design for open-core separability; defer the sustainability decision explicitly. |
| D22 | Disclose AI authorship (commit trailers + CONTRIBUTING.md); owner signs and takes responsibility. |

## Recommended Phase 1 cuts (architecture reviewer, consistent with D7)

**Cut:** React investigation UI (CLI/SQL over the audit store instead) · distributed/versioned
policy control plane (a local policy file is enough for a fleet of one) · full OTel span
coverage · any breadth beyond one event type.

**Add:** the fail-open watchdog PoC (D18) · named audit-storage decision (D12) · a hard second
fitness case (A1) · reconciliation of intake.md against D1-D22.

## Process finding

`intake.md` still described a Rust agent and `ClipboardCopied` in its definition of done after
D8 and D2 superseded both. For a project whose doctrine is "decide the hard-to-change things
first," letting the source-of-truth doc drift is a process bug. Reconciled 2026-07-20.

## Reviewer caveat

All four reviewers were given `scouting-r1.md`, so they inherited its framing and D1-D9. That is
efficient but anchoring: a flawed premise established in round 1 could survive this review
un-challenged. These findings check the decisions; they do not independently prove the
foundations.
