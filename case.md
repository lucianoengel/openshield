---
id: openshield
title: OpenShield – Open Source Data Security Platform
profile: engineering
sensitivity: general
status: open
created: 2026-07-20
notion: https://app.notion.com/p/OpenShield-Open-Source-Data-Security-Platform-3a33a4b5b2f28137b137ff0ee6f70d27
---
> **Process file.** Working log for the homelab case workflow, in chronological order.
> **Decisions are NOT canonical here** — see [`docs/decisions.md`](docs/decisions.md).
> Entries below are a historical record of when things were decided, not the current state.

# OpenShield – Open Source Data Security Platform

See **intake.md** for the assignment brief. This file is the working log.

## Problem statement
Build a modular, open-source Data Security Platform (DSP) whose universal
Event → Classification → Policy → Decision → Enforcement → Audit pipeline stays fixed for a
10+ year roadmap; DLP is only the first capability on top of it.

## Known facts
- **2026-07-20 — case opened.** Greenfield; nothing built. Registered in lab graph
  (`note:case:openshield`) and the Notion Cases DB.
- **Recall came back empty.** No prior DLP / data-security case in the workspace to build on.
  Nearest neighbours are architectural-rigour precedents, not domain reuse:
  - `merit` — Phase-0 scouting pattern: audited-implementation sourcing, spec converged over
    numbered adversarial review rounds until clean. The right template for locking the event
    schema and Decision contract before writing code.
  - `openpeer` — existing Rust protocol workspace; reusable shape for a Rust agent crate.
- **Domain skills exist but are operator playbooks, not build guides** — `implementing-endpoint-dlp-controls`,
  `implementing-cloud-dlp-for-data-protection`, `implementing-data-loss-prevention-with-microsoft-purview`,
  `detecting-insider-threat-with-ueba`, `implementing-policy-as-code-with-open-policy-agent`.
  Value here is **requirements extraction** (what operators actually configure and complain
  about) rather than method. Purview and OPA ones are the highest-signal for the policy model.

- **2026-07-20 — owner decisions.** Licence **Apache-2.0** (permissive as asked; picked over
  MIT for the patent grant). Forcing function = **portfolio + genuine self-use**, which scopes
  the MVP to **Linux-first, dogfooded on the owner's own fleet**, and defers the Windows
  driver and macOS entitlement out of the MVP.

- **2026-07-20 — Round-1 scouting done** → `docs/research-scouting-r1.md` (3 parallel scouts).
  Headline: two scouts independently converged on **Phase 1 should be observe-only, not
  blocking**. Key findings: clipboard DLP is architecturally prevented on Wayland; fanotify
  permission events can hang the whole machine if the agent stalls (fail-open is a
  first-commit requirement); CEL's Rust-side conformance is unproven despite appearances;
  prior OSS DLP died of **maintenance economics**, not bad detection; Presidio's ~22.7%
  precision on person-names means Policy must treat Classification as noisy.
  D1-D5, D7 proposed and confident; **D6 (policy IR) is an open owner call**.

- **2026-07-20 — D8 all-Go** (supersedes the brief's Rust-agent/Go-backend split). Owner does
  not write code, so work is agent-driven and owner-reviewed: Go converges in fewer
  compile-fix cycles and is reviewable by a non-coding owner — the only real oversight
  mechanism here. One language ⇒ one shared policy engine ⇒ **D6 parity problem disappears**.
- **2026-07-20 — D9 Windows/macOS via GitHub Actions runners, not local VMs.** Podman cannot
  grant KVM (verified). Windows: VM solves dev, EV cert solves shipping. macOS: blocked by
  Apple EULA (Apple hardware only) + selectively-granted ES entitlement — not an infra problem.
  **No host access requested; not needed for Phase 1.**
- **2026-07-20 — M1 measured (dev sandbox only, NOT a design input):** unprivileged fanotify
  `FAN_REPORT_FID` works here with no caps; blocking modes EPERM, and rootless Podman
  `--cap-add SYS_ADMIN` does not help. **Scope discipline (owner challenge, same day):** the
  shipped agent runs as root with full capabilities, so nothing about this sandbox constrains
  the architecture. M1/R1 answer only "how far does the local build loop get before we ask for
  a host change." If the loop needs a capability, ask for it — do not redesign around it.

- **2026-07-20 — Round-1 adversarial review done** → `docs/research-review-r1.md` (4 reviewers:
  architecture, applied crypto, red team, privacy law + OSS sustainability). **The pipeline
  architecture largely survives; the brief's stated principles do not.** Three reviewers
  independently found OpenShield promising properties it cannot deliver:
  - **Privacy model is false as written** — hashing low-entropy PII (SSN/**CPF**/cards/DOB) is
    theatre; embeddings are invertible (vec2text 92%). → D10, D11.
  - **"Tamper-proof" unachievable** in one self-hosted trust domain → forward-integrity +
    external anchoring; say "tamper-evident". → D12.
  - **Root user defeats any host agent** → tamper-*detection*, not prevention. Dogfooding
    cannot validate the product as a control. → D16.
  - **Agent makes machines less secure** unless privilege-split + parser sandboxed
    (cf. ClamAV CVE-2025-20260 PDF-parser RCE). → D13.
  - **Hub content-hash trust = fleet-wide root-equivalent supply chain risk** → ed25519
    per-author signing; offline revocation is unsolved, document it. → D15.
  - **The "zero core diffs" fitness test measures the wrong axis** (S3 is isomorphic to what
    exists; trivially gamed) → add a hard stateful/catalog case.
  - **D8 all-Go should be scoped**, not blanket — GC jitter in the fanotify permission window
    is the worst failure mode; spike before locking Go for the responder. → D19.
  - Pipeline genuinely leaks for UEBA (stateful baselines), Discovery (catalog), Lineage (graph).
  - Privacy law → concrete Phase-1 product requirements (DPIA, retention, exclusion lists,
    four-eyes, view-auditing). German works councils hold an **absolute veto**. → D20.
  - AI-authored code may not be copyrightable → undercuts the Apache-2.0 patent-grant
    rationale; disclose authorship, owner signs. → D22.
  D10-D22 proposed. Phase 1 cut: React UI, distributed policy plane, full OTel.
- **2026-07-20 — process fix:** `intake.md` had drifted (still said Rust agent + clipboard
  after D8/D2 superseded them). Reconciled; threat model and reworded privacy claim added.

- **2026-07-20 — D23 UEBA: both modes, gated.** Self-baseline computed locally on the endpoint
  (on by default); peer-baseline as an **optional server-side Analytics module, off by
  default**, with its own consent/DPIA gate. Resolves the brief's silent contradiction between
  "Peer Analysis" and "server coordinates, does not compute". Phase 1 consequence is one
  schema field (stable pseudonymous user ID) so peer analysis needs no later migration.
  **Peer-UEBA doubles as the "hard" fitness case (A1)** — stateful, aggregating, cross-entity;
  design on paper before building, to test the zero-core-change claim cheaply.
- **2026-07-20 — repo: GitHub, public, Apache-2.0** (org/account at creation). Public also
  unlocks free Windows/macOS runners (D9). **"Hours/week" dropped** — wrong question for an
  agent-built project; the binding constraint is owner *decision latency*, generally same-day.

## Unknowns
**Superseded — see [`docs/decisions.md`](docs/decisions.md) § Known open questions.**
The two listed here originally (policy IR across Rust/Go; licence choice) are both resolved:
D8 dissolved the policy-IR problem by going single-language, and the licence is Apache-2.0.
The one genuinely open decision is **D19** — the GC-pause measurement (T-002).

## Working notes
- Next: `deep-research` scout on prior art (CrowdSec hub/decision model, OPA, Presidio,
  Wazuh, Velociraptor, osquery, incumbent DLPs) and the policy-IR decision → then plan mode
  → tickets via `bootstrap/scripts/tickets.py`.
- Backend stack (Go/NATS/Postgres) likely needs a dev pod: `dev_env up openshield`.
