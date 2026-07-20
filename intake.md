# Intake Brief — internal

> **Process file.** This is the internal assignment brief for the homelab case workflow.
> **Decisions are NOT canonical here** — [`docs/decisions.md`](docs/decisions.md) is the single
> source of truth for D-numbers. This file references them; it must not restate them. (It drifted
> out of sync twice by restating them, which is why the register exists.)
> Public-facing docs: [`README.md`](README.md) · [`docs/threat-model.md`](docs/threat-model.md)

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
> **Reconciled 2026-07-20** against `docs/research-scouting-r1.md` (D1-D9) and
> `docs/research-review-r1.md` (D10-D22). Earlier text described a Rust agent and clipboard events;
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
Greenfield. Repo: `github.com/lucianoengel/openshield` (public, Apache-2.0), first commit is
this decision record. **Settled stack** — the brief's proposal, as amended by D8/D19:

| Layer            | Decision                        | Note |
|------------------|---------------------------------|------|
| Endpoint agent   | **Go** (was Rust in the brief)  | D8 — single language kills the cross-runtime parity problem |
| fanotify responder | **Go, pending T-002**         | D19 — GC-pause spike may carve this one component out to cgo/Rust |
| Backend          | Go                              | |
| Policy engine    | **OPA/Rego, native Go**         | D6 collapsed once the language split went away |
| Windows driver   | *deferred out of MVP*           | EV cert + Windows test env; fleet is Linux |
| Frontend         | React + TS — **cut from Phase 1** | CLI/SQL over the audit store instead |
| Database         | PostgreSQL — **also the audit ledger** | D12: hash-chained system of record |
| Message bus      | NATS JetStream — **bus only**   | D12: bounded retention ≠ system of record |
| Object storage   | S3-compatible                   | evidence storage, later phase |
| Protocol         | gRPC + Protobuf                 | |
| Observability    | OpenTelemetry — **cut from Phase 1** | structured logging only for now |
| Deployment       | **Podman** Compose; K8s optional | no Docker on this host |

## Stack limitations / known pain
- ~~Two-language split~~ — **resolved by D8.** One language means one shared policy engine, so
  the "same policy, two implementations, one answer" correctness risk no longer exists. This
  was the single biggest risk in the original design and it was deleted rather than solved.
- ~~Policy IR portability~~ — **resolved with it.** OPA/Rego runs natively in Go; no CEL, no
  WASM, no custom IR. WASM stays relevant only for sandboxing untrusted Hub packs (Phase 3+).
- **Remaining hot-path risk (D19, open until T-002):** GC pauses and scheduler jitter inside a
  live fanotify permission window. Worst failure mode in the system — a stalled responder parks
  processes in `TASK_UNINTERRUPTIBLE`. Measurement decides; unverified is the failure.
- **Classification accuracy is the hard problem** — Presidio benchmarks ~22.7% precision on
  person names. Policy must consume confidence, never a clean boolean (D4).
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
- **Go toolchain** (D8). Rust tooling on this host is no longer relevant to the build.
- **Repo: `github.com/lucianoengel/openshield`** — public, Apache-2.0, created 2026-07-20.
  Public also unlocks free `windows-latest`/`macos-latest` runners (D9).
- Likely needs a dev pod (`dev_env up openshield`) for the Go/NATS/Postgres stack.
- Windows/macOS test targets: **GitHub Actions runners** (D9), not local VMs. `/dev/kvm` here
  is ACL'd to another user and rootless Podman cannot confer KVM or real `CAP_SYS_ADMIN` — but
  that is a dev-loop fact, never a design input. Windows *driver* work needs a real target and
  an EV cert; both are deferred with the platform.

## Definition of done & quality bar
- The 6-step end-to-end slice above, demoable from a clean `podman compose up`.
- **Architectural fitness test in CI**: adding a Connector/Enforcer must produce zero diffs in
  core packages — enforced by a test, not by discipline.
- ~~Policy-engine parity test~~ — **obsolete under D8.** One language, one policy engine, one
  implementation. Replaced by: identical policy + input → identical Decision (determinism
  within the single engine).
- Enforcement plugins provably receive Decisions only, with a **closed, typed action set**
  (D14) — enforceable at the type level, not by convention.
- Audit log tamper-evidence demonstrated by an actual tampering test (T-009), with external
  anchoring (T-019) so the claim is "tamper-evident between anchors", never "tamper-proof".
- **Negative properties asserted by test, not inspection** — they rot silently otherwise:
  import allowlist via `go list -deps` proving the privileged process cannot parse untrusted
  bytes (T-006); wire-byte grep proving no content or reversible hash leaves the endpoint
  (T-007); CI denylist grep on overclaiming words in docs (T-001).
- TDD for core pipeline logic. OpenTelemetry is **cut from Phase 1**; structured logging only.

---
## Entry points (where we start)
Superseded by the ticket queue — see `tickets.jsonl` / `tickets.md` and `docs/plan-phase1.md`.
Order: **T-001** repo+governance → **T-002** GC spike (could partly reverse D8) → **T-003**
schema+Decision contract → **T-004** peer-UEBA paper test (cheapest test of the 10-year claim).

## Open unknowns
**Resolved by round-1 research** (`docs/research-scouting-r1.md`) — kept only as pointers:
- ~~Prior art~~ → CrowdSec decision-separation, Presidio limits, and the OSS-DLP graveyard
  (MyDLP acquired, OpenDLP abandoned, Metron retired — all died of maintenance economics).
- ~~Policy IR across two languages~~ → dissolved by D8; OPA/Rego native in Go.
- ~~NATS sufficiency for audit~~ → no. D12: Postgres is the system of record, JetStream is a bus.
- ~~Linux interception mechanics~~ → fanotify perm events block open/read/exec (not
  rename/unlink); BPF-LSM is v2; Landlock cannot police other processes.
- ~~Clipboard~~ → D2, cut. Wayland architecturally prevents system-wide observation.
- ~~Browser upload~~ → cut from Phase 1 (needs an extension or TLS proxy, not a kernel hook).

**Still genuinely open:**
- **D19 / T-002** — does Go's GC jitter break the fanotify permission window? Empirical, and it
  is the last decision resting on measurement rather than argument.
- **Phase-1 infrastructure coverage** — the plan was decomposed from *decisions*, so it has
  blind spots wherever nothing was contested: event bus/dispatcher, control-plane service,
  offline store-and-forward queue, compose dev stack, DB migrations, packaging. ~8 tickets
  identified 2026-07-20, not yet written. **Owner decision pending.**
- **A2 shape questions** — Data Discovery (a catalog, not an event stream) and Lineage (a graph)
  have no home in the frozen pipeline. T-004 tests only the UEBA sliver.
- Whether cross-endpoint peer baselining is ever enabled by default (D23 says no).

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
