# Intake Brief — internal

- **Case / slug:** openshield
- **Profile:** engineering
- **Client / contact:** internal
- **Data sensitivity:** general — the platform itself is fully open source; any *test corpora*
  containing real PII stay in the homelab and never reach Notion or a public repo.
- **Date / owner:** 2026-07-20 · Luciano Engel

## The problem (in their words)
Build a modular, open-source Data Security Platform (DSP) whose universal
Event → Classification → Policy → Decision → Enforcement → Audit → Investigation → Analytics
pipeline stays fixed for a 10+ year roadmap; DLP is only the first capability on top of it.

Explicitly **not** "another DLP tool". The bet is that every future capability (Cloud DLP,
Email DLP, AI Security, Data Discovery/Classification/Lineage, Insider Risk, UEBA, SaaS
Protection, Developer Security, Enterprise Governance) is expressible as *new Event producers,
Classifiers, Policies and Enforcers* — with zero changes to the core.

## Desired outcome — what "done" looks like
> **Reconciled 2026-07-20** against `reports/scouting-r1.md` (D1-D9) and
> `reports/review-r1.md` (D10-D22). Earlier text described a Rust agent and clipboard events;
> both are superseded (D8 all-Go for backend/non-hot-path; D2 drops clipboard — Wayland
> prevents system-wide observation).

The MVP is done when a **Phase 1 Endpoint DLP** slice runs end to end on the fixed pipeline,
**observe-and-audit only** (D1 — no blocking enforcement in Phase 1):

1. A Go endpoint agent emits real events: `FileOpened`/`FileModified` (fanotify) and
   `USBInserted`. **No clipboard events** (D2 — Wayland prevents it).
   **`BrowserUploadStarted` is CUT from Phase 1** (recorded 2026-07-20 after plan review):
   it needs either a per-browser extension or a TLS-terminating proxy, neither of which is a
   kernel hook, and both are substantial work that proves nothing the file path doesn't.
   Deferred to Phase 2 — recorded as a decision here rather than left to drift silently out of
   the ticket list, which is how it was first lost.
2. Classification runs **locally on the endpoint**, patterns/deny-lists only (D5), in a
   **separate unprivileged sandboxed worker** — the privileged process never parses untrusted
   bytes (D13). Only **type + confidence + count** leaves the endpoint (D10).
3. A local policy file is evaluated **locally** and yields a standardized `Decision` carrying
   confidence, not certainty (D4). Distributed/versioned policy control plane is **cut** from
   Phase 1 — a fleet of one does not need it.
4. The Enforcer interface exists with a **closed, typed action set** (D14) and receives *only*
   the Decision — never which classifier or regex produced it (CrowdSec separation). Verdicts
   are always-allow in Phase 1, but **the fail-open timeout watchdog is built and exercised
   for real** with injected delay (D18) — that is the risky contract, and it gets proven now.
5. The Decision lands in a **tamper-evident, forward-integrity** audit log — Postgres
   hash-chain, JetStream is bus only (D12) — queryable via CLI/SQL. **React UI is cut** from
   Phase 1.
6. A second capability is added by writing **only** a Connector — **no core diffs**, enforced
   by CI. Note (A1): an S3 connector is structurally isomorphic to what exists and proves
   little. A **second, harder fitness case** (stateful or catalog-shaped) is required before
   the abstraction is considered validated.

**Privacy-law features are Phase-1 architecture, not later additions** (D20): retention limits
with automatic purge, purpose tagging at schema level, exclusion lists as a first-class policy
primitive, pseudonymisation by default, and an audit trail of *who viewed an investigation*.

## Why now (forcing function)
**Portfolio artifact + genuine self-use** (owner, 2026-07-20). No external deadline; the
forcing function is **dogfooding on the owner's own homelab fleet**.

This is a real constraint, not a soft one, and it drives scope:
- The fleet is **Linux**. Therefore **Linux-first** (fanotify / eBPF / LSM). The Windows
  minifilter driver and the macOS Endpoint Security entitlement — the two most gated, highest-
  cost items in the brief — are **deferred out of the MVP entirely**. They are not on the path
  to something the owner runs, and neither is testable on this host today.
- "Runs on my machines and I trust it" is a sharper and more honest bar than "demoable".
  It forces real operability: install, upgrade, low idle overhead, no false-positive storms,
  and a fail-open story when the agent dies.
- Portfolio value follows from the architecture being genuinely sound under real use — not
  from breadth of half-working connectors.

## Hard constraints
- Fully open source; self-hostable; cloud-agnostic; air-gap friendly; offline-capable.
- Privacy-first. **Reworded 2026-07-20 after review — the original claim was false as stated.**
  "Prefer hashes/fingerprints" does **not** provide confidentiality for the low-entropy
  identifiers this product targets (SSN 10^9, **CPF ~10^9**, credit cards ~10^7 effective after
  BIN+Luhn, DOB ~36.5k — all brute-forceable in minutes-to-hours; salting does not fix it).
  Nor do embeddings/fuzzy fingerprints de-identify: vec2text recovers 92% of 32-token inputs
  exactly. The real controls are: format+checksum detection locally, transmitting only
  **type + confidence + count** (D10); embeddings and fuzzy fingerprints treated as
  **content-equivalent** — encrypted, access-controlled, never in the Hub (D11).
- Server **coordinates**, does not continuously control. Classification, policy evaluation and
  enforcement happen locally whenever technically possible.
- Detection and enforcement stay **completely decoupled** — enforcers receive Decisions only.
- Installing a new capability must never require modifying the platform core.
- Zero Trust oriented, API-first, event-driven, plugin-based.
- **Licence: Apache-2.0** (owner call, 2026-07-20 — "normal open source, everyone can do
  whatever they want"). Permissive as requested; chosen over MIT for the explicit **patent
  grant**, which matters in a patent-dense field with well-funded incumbents. A vendor may
  host it as closed SaaS — accepted, and consistent with the stated intent.

## UEBA / behavioural analytics — both modes, gated (D23, 2026-07-20)
The brief lists "Peer Analysis", which silently contradicts *"the server coordinates, does not
compute"*. Resolved by supporting **both** baselining modes with different homes:

- **Self-baseline** (you vs your own history) — computed **locally on the endpoint**. On by
  default. Fully consistent with the local-first principle.
- **Peer-baseline** (you vs role/department peers) — an **optional server-side Analytics
  module** consuming the existing event stream. **Off by default**, installed per deployment,
  with its own consent/DPIA gate. Requires the server to hold per-user behavioural profiles,
  which is the shape works councils veto and DPAs fine over — so the *default* is the privacy
  statement, even though the deployer (not the author) bears controller liability.

**Phase 1 consequence: exactly one field** — a stable *pseudonymous* user ID in the event
schema, so peer analysis stays possible later without a migration. Nothing else is built.

**Peer-UEBA is also the "hard" architectural fitness case** (review A1): stateful, aggregating,
cross-entity, needing persisted baselines rather than per-event verdicts — it breaks every
assumption the DLP-shaped pipeline makes, unlike an S3 connector which is isomorphic to what
already exists. **Design it on paper before building anything.** If it expresses cleanly as an
Analytics module with no core changes, the 10-year bet is real; if it forces core changes, that
is discovered in week one on paper rather than year three in code.

## Threat model — what this product can and cannot promise
**Added 2026-07-20 after red-team review. This was the brief's largest unstated assumption.**

| Adversary | Stoppable by a host agent? |
|---|---|
| Careless insider, no intent | **Yes** — this is the design centre |
| Malicious insider, no local admin | **Partially** — only on hooked paths |
| Malicious insider **with root on their own machine** | **No** |
| External attacker who has compromised the host | **No** |

Anyone with root can `systemctl stop`/`mask` the agent, boot a live USB, mount the disk
elsewhere, exfil from a VM, or block egress so nothing ever syncs. There is no fix that does
not require distrusting the OS the agent depends on. **The honest goal is tamper-*detection*
(heartbeat / dead-man's-switch / "agent last seen"), never tamper-prevention** (D16).

**Consequence for the dogfood plan:** the owner has root on his own fleet, so dogfooding is the
bottom-half case. It validates the pipeline, classifier, plumbing and operability bar — it
**cannot** validate the product as a control. Expected, not a failure.

**README must claim:** local-first visibility, friction for careless insiders, a tamper-evident
trail. **Must not claim:** prevention of exfiltration, tamper-proofing, or efficacy against
motivated actors. The first researcher who runs `systemctl stop` will disprove anything stronger.

## Stakeholders & decision-maker
Luciano Engel — sole owner, architect and sign-off. No external stakeholders yet.
> TODO — is there an intended contributor community / early design partner, or is this
> solo-build for the foreseeable future?

---
<!-- ── BUILD / ENGINEERING profile ─────────────────────────────────────────── -->
## Current stack
Greenfield — nothing exists yet. Repo root is this case dir (`~/workspace/openshield`).
Proposed stack from the brief (**to be validated during research, not assumed**):

| Layer            | Proposal                        |
|------------------|---------------------------------|
| Endpoint agent   | Rust                            |
| Windows driver   | C/C++ (minifilter / WFP)        |
| Backend          | Go                              |
| Frontend         | React + TypeScript              |
| Database         | PostgreSQL                      |
| Message bus      | NATS JetStream                  |
| Object storage   | S3-compatible                   |
| Protocol         | gRPC + Protobuf                 |
| Observability    | OpenTelemetry                   |
| Deployment       | Docker Compose; K8s optional    |

## Stack limitations / known pain
Risks inherent in the proposal, to be pressure-tested before committing:
- **Two-language split (Rust agent / Go backend)** duplicates the event schema and policy
  evaluator across runtimes. Protobuf mitigates the wire format; it does not mitigate a
  policy engine that must behave *identically* on both sides. This is the single biggest
  correctness risk in the design — same policy, same input, two implementations, one answer.
- **Local policy evaluation** requires compiling policies to a portable runtime representation
  that Rust can execute offline and deterministically (candidates: CEL, Rego/OPA-wasm, a
  purpose-built IR). Choice constrains the 10-year roadmap.
- ~~Windows kernel work~~ — **deferred out of MVP** (needs EV code signing + a Windows test
  environment, neither of which exists here, and the owner's fleet is Linux). Retained as a
  design constraint only: the Connector/Enforcer interfaces must not bake in Linux assumptions.
- **Air-gap + Hub** are in tension: a community hub implies distribution, update and
  signature-verification design that works fully offline.
- NATS JetStream must satisfy the stated replay/audit/long-retention requirement, or the
  event log needs a separate durable tier.

## Environments
- Dev: this host (Linux, rootless Podman — **not** Docker) + dev pod when tooling is missing.
- **Endpoint agent: Linux only for the MVP** (fanotify / eBPF / LSM), dogfooded on the owner's
  own fleet. Windows and macOS agents stay in the architecture (the Connector abstraction must
  not assume Linux) but are **out of MVP scope** — see § Why now.
- No staging/prod yet — self-hosted demo stack via Podman Compose is the first target.

## Tooling & access
- Containers: **Podman rootless only** (no Docker, no sudo, not in docker group).
- Rust toolchain + cargo-mcp/cratedex available for docs & diagnostics.
- **Repo: GitHub** (owner call, 2026-07-20). Public, Apache-2.0. Exact org/account settled at
  creation time. Public repo also unlocks free `windows-latest`/`macos-latest` runners (D9).
- Likely needs a dev pod (`dev_env up openshield`) for the Go/NATS/Postgres backend stack.
- > TODO — Windows test target for driver work (VM? spare machine? none?).

## Definition of done & quality bar
- The 6-step end-to-end slice above, demoable from a clean `podman compose up`.
- **Architectural fitness test in CI**: adding a Connector/Enforcer must produce zero diffs in
  core packages — enforced by a test, not by discipline.
- Policy-engine parity test: identical policy + input → identical Decision in Rust and Go.
- Enforcement plugins provably receive Decisions only (no classifier detail on the interface —
  enforceable at the type level).
- Audit log tamper-evidence demonstrated by an actual tampering test.
- TDD for core pipeline logic; OpenTelemetry traces spanning event → decision → enforcement.

---
## Entry points (where we start)
1. **The event schema and the `Decision` contract** — everything else is downstream of these
   two, and they are the hardest things to change later. Design them first, in Protobuf.
2. The policy IR choice (CEL vs Rego/wasm vs custom), because it constrains 1.
3. Only then: the thinnest possible vertical slice (one event, one classifier, one policy,
   one enforcer) to prove the pipeline before widening it.

## Open unknowns
- **Prior art**: how do CrowdSec (hub + decision model), OPA, Presidio, Wazuh, Velociraptor,
  osquery and the incumbent DLPs (Purview, Nightfall, Cyberhaven) actually structure this?
  Where has open-source DLP been tried and failed, and why? — first research target.
- Policy IR that is offline, deterministic, sandboxed and executable from both Rust and Go.
- Whether NATS JetStream alone satisfies replay + long-term audit, or needs a durable tier.
- **Linux interception mechanics** — fanotify vs eBPF vs LSM/BPF-LSM for file, clipboard, USB
  and process events: which give *blocking* (pre-operation) hooks vs observe-only, what each
  costs in privilege (CAP_SYS_ADMIN? root?), kernel-version floor, and idle overhead. Blocking
  capability is the crux: an enforcer that can only observe cannot implement `Block`.
  (Windows/macOS mechanics deferred with the platforms themselves.)
- Clipboard and browser-upload interception on Linux specifically — Wayland vs X11 changes
  this completely, and Wayland deliberately restricts clipboard access. May be the hardest
  MVP event to source honestly.
- Realistic MVP scope for a solo builder — the brief describes a decade of work; the honest
  question is which single slice earns the right to build the rest.

## Success criteria & timeframe
- Success = the pipeline abstraction survives contact with the *second* capability without
  core changes. If adding S3 forces a core diff, the abstraction is wrong and it is far
  cheaper to learn that in week two than in year two.
- Cadence: agent wall-clock is not the binding constraint here — the schedule is driven by
  human gates (licence call, repo creation, Windows/macOS test targets, code-signing certs).
- The dogfood bar: **the owner runs it on his own fleet and trusts it.** That means install,
  upgrade, low idle overhead, no false-positive storms, and fail-open when the agent dies —
  operability is part of done, not a later phase. Note the threat-model caveat above: this
  validates pipeline/classifier/operability, **not** the product as a control.
- **The binding constraint is decision latency, not build hours.** Agents build continuously;
  progress stalls at gates needing the owner (design calls, licence/legal posture, anything
  touching his fleet). "Hours/week" was the wrong question for an agent-built project and has
  been dropped. Owner is generally available same-day.
