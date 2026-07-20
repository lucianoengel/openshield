# Project Brief

Why OpenShield exists, what "done" means, and the constraints that shaped it. Decisions
themselves live in [`decisions.md`](decisions.md) — this file references them by number and
never restates them.

## The problem, as originally stated

> Build a modular, open-source Data Security Platform whose universal
> Event → Classification → Policy → Decision → Enforcement → Audit → Investigation → Analytics
> pipeline stays fixed for a 10+ year roadmap; DLP is only the first capability on top of it.

Explicitly **not** "another DLP tool". The bet is that every future capability — Cloud DLP,
Email DLP, AI Security, Data Discovery, Classification, Lineage, Insider Risk, UEBA, SaaS
Protection, Developer Security, Enterprise Governance — is expressible as *new Event producers,
Classifiers, Policies and Enforcers*, with zero changes to the core.

That bet has now been tested on paper ([T-004](design-t004-peer-ueba.md)) and it is **partly
false**. Peer-baseline UEBA needs its risk score to reach Policy, which is a feedback edge a
linear pipeline cannot express — so it requires a small core addition (an enrichment Context,
and a `context_version` on Decision). The corrected claim is that capabilities of the same
*shape* need no core change, while a new *shape* of data flow needs a small, identifiable one.

Finding that on paper cost an afternoon. Finding it after the hash-chained audit ledger existed
would have cost a migration and a break in the chain's continuity.

## Why now

**Portfolio artifact plus genuine self-use.** No external deadline; the forcing function is
dogfooding on the owner's own homelab fleet. That is a real constraint and it drove scope:

- **The fleet is Linux**, so the project is Linux-first. The Windows minifilter driver and the
  macOS Endpoint Security entitlement — the two most gated, highest-cost items in the original
  brief — are deferred out of the MVP entirely (D9). They are not on the path to something the
  owner actually runs.
- **"Runs on my machines and I trust it"** is a sharper bar than "demoable". It forces real
  operability: install, upgrade, low idle overhead, no false-positive storms, and a defined
  fail-open story when the agent dies.
- Portfolio value follows from the architecture being sound under real use, not from breadth of
  half-working connectors.

**One honest caveat:** the owner has root on the dogfood fleet, which is exactly the case a host
agent cannot defend against ([`threat-model.md`](threat-model.md)). Dogfooding validates the
pipeline, classifier, plumbing and operability bar. It cannot validate the product as a control.

## What "done" means for Phase 1

Phase 1 is **observe-and-audit only** (D1) — Decisions are recorded, not enforced. Enforcement
lands in Phase 2, once the classifier's real false-positive rate is known from live data.
A DLP tool that blocks on a noisy classifier is hostile to its own users.

The slice is done when:

1. A Go endpoint agent emits real events — `FileOpened`/`FileModified` via fanotify, and
   `USBInserted`. No clipboard events (D2). `BrowserUploadStarted` is cut from Phase 1: it needs
   a browser extension or a TLS-terminating proxy, neither of which is a kernel hook.
2. Classification runs locally, patterns and deny-lists only (D5), inside a separate
   unprivileged sandboxed worker — the privileged process never parses untrusted bytes (D13).
   Only type + confidence + count leaves the endpoint (D10).
3. A local policy file is evaluated locally and yields a `Decision` carrying confidence (D4).
   No distributed policy control plane in Phase 1 — a fleet of one does not need one.
4. The Enforcer interface exists with a closed, typed action set (D14) and receives only the
   Decision. Verdicts are always-allow, but **the fail-open timeout watchdog is built and
   exercised for real** (D18) — that is the risky contract and it gets proven now.
5. The Decision lands in a tamper-evident, forward-integrity audit log (D12), queryable by CLI.
   No React UI in Phase 1.
6. A second capability is added by writing only a Connector, with zero core diffs enforced by
   CI — paired with the T-004 paper verdict, because an S3 connector is isomorphic to what
   already exists and proves little on its own.

Privacy-law features are Phase-1 architecture, not later additions (D20).

## Quality bar

- **Negative properties are asserted by test, never by inspection** — they rot silently
  otherwise. Import allowlist via `go list -deps` proving the privileged process cannot parse
  untrusted bytes; wire-byte scan proving no content or reversible hash leaves the endpoint;
  CI checks on claim surfaces.
- **Prefer mechanism over discipline.** Automated gates carry unusual weight here because they
  substitute for the line-level review depth a non-coding maintainer cannot provide.
- Enforcement plugins provably receive Decisions only, enforced at the type level.
- TDD for core pipeline logic. OpenTelemetry is cut from Phase 1; structured logging only.

## Constraints

Fully open source · self-hostable · cloud-agnostic · air-gap friendly · offline-capable ·
Zero Trust oriented · API-first · event-driven · plugin-based · the server **coordinates**, it
does not continuously control · installing a new capability must never require modifying the
core.

Privacy-first — but see D10/D11 for what that actually means. The original brief's "prefer
hashes and fingerprints" claim was false as written: low-entropy identifiers are brute-forceable
and embeddings are invertible.

## Stack

| Layer | Decision | Note |
|---|---|---|
| Endpoint agent | **Go** | D8 — single language kills the cross-runtime parity problem |
| fanotify responder | Go, **pending T-002** | D19 — GC-pause spike may carve this one component out |
| Backend | Go | |
| Policy engine | OPA/Rego, native Go | D6 collapsed with the language split |
| Database | PostgreSQL | also the hash-chained audit ledger (D12) |
| Message bus | NATS JetStream | **bus only** — bounded retention is not a system of record |
| Protocol | gRPC + Protobuf | |
| Frontend | React + TS | **cut from Phase 1** — CLI/SQL instead |
| Observability | OpenTelemetry | **cut from Phase 1** |
| Deployment | Podman Compose | K8s optional; no Docker on the dev host |
| Windows driver | *deferred* | EV cert + Windows test target (D9) |

## Environments

Dev is the owner's Linux host plus a dev container when tooling is missing. The endpoint agent
targets Linux only for the MVP; Windows and macOS remain in the architecture — the Connector
and Enforcer interfaces must not bake in Linux assumptions — but build and test only via
GitHub Actions runners (D9). No staging or production yet; a self-hosted stack via Podman
Compose is the first target.

## Owner

Solo. Luciano Engel — architect, reviewer and sign-off. The code is written by AI agents under
direction (D22, and [`../CONTRIBUTING.md`](../CONTRIBUTING.md)).

The binding schedule constraint is **decision latency**, not build hours: agents build
continuously and stall at every gate that needs a human.

*Open: whether there is an intended contributor community or early design partner, or whether
this stays solo for the foreseeable future.*
