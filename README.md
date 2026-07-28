<div align="center">

<img src=".github/assets/banner.svg" alt="OpenShield" width="100%">

<br/>

[![CI](https://github.com/lucianoengel/openshield/actions/workflows/ci.yml/badge.svg)](https://github.com/lucianoengel/openshield/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/lucianoengel/openshield)](https://goreportcard.com/report/github.com/lucianoengel/openshield)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](go.mod)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange.svg)](#-project-status)
[![Platform](https://img.shields.io/badge/platform-Linux-333?logo=linux&logoColor=white)](#-components)

**One pipeline. Every layer. Tamper-evident by design.**

A pipeline-native **XDR + SOAR** data-security platform — DLP, HIPS, network prevention, SIEM,
and Zero-Trust access, unified by a single detection-and-response pipeline and a forward-secure,
externally anchored audit ledger that makes *every* decision independently verifiable.

[Roadmap](docs/architecture-roadmap.md) · [Architecture](#-architecture) · [Decisions](docs/decisions.md) · [Threat model](docs/threat-model.md) · [Contributing](#-contributing)

</div>

---

> ### ⚠️ Project status
> **OpenShield is pre-alpha.** The **observe path runs end-to-end as a binary** — a real file
> dropped in a watched directory is classified in a sandboxed worker, evaluated against policy, and
> lands an `ALERT` in the hash-chained ledger (the integration suite, `make integration`). A fleet
> control plane, mutual-TLS transport, network gateway, HIPS process pipeline, cross-domain
> correlation and SOAR orchestration are built and tested.
>
> **Inline prevention is real** and proven on a live kernel: an execution is refused by the kernel,
> on a verdict from the full pipeline. Inline blocking of a file **open** remains designed and not
> wired.
>
> **What "pre-alpha" still means here:** there is no published release (the signing, SBOM and
> verification tooling exists; nothing has been cut with it), durability is single-node, there is
> **no analyst UI**, and nothing here has run in production anywhere. The maturity table below names
> what is missing per domain, and the [unwired-feature audit](docs/unwired-audit.md) is a running log
> of the times something looked finished and was not.

## 🔍 Overview

Most security suites bolt DLP, EDR, NDR, and SIEM together as separate products with separate
data models. OpenShield is the opposite bet: **one fixed pipeline** absorbs every capability as a
plugin, so a network detector, an endpoint process rule, and an identity signal all flow through
the same stages and land in the same tamper-evident evidence store.

```
Event → Classify → Policy → Decision → Enforce → Audit     ·     (above the pipeline) Investigate · Analyze · Respond
```

New capability arrives as a new **Producer** (event source), **Classifier** (detector),
**Policy** input, or — rarely and deliberately — **one new typed Action**. The core never changes.
That discipline is what lets OpenShield span seven security domains without becoming seven codebases.

## ✨ Why OpenShield

- **🔗 One pipeline, every domain.** Endpoint files, process exec, DNS, SMTP, USB, and network flows
  are all just *Events*. Add a producer, reuse the whole stack.
- **🛡️ The control plane cannot actuate.** The `Action` set is **closed, typed, and
  parameterless** — a compromised server can place a subject under containment, but can never
  express "run this command." Enforcement decisions are made *locally*; the server coordinates, it
  does not control.
- **🔒 Content never leaves the sandbox.** Untrusted bytes are parsed in a seccomp-hardened worker
  with no network; only **type + count + metadata** cross the boundary — never the sensitive content
  itself.
- **⛓️ Every decision is evidence.** A per-agent, forward-secure, hash-chained ledger with external
  anchoring makes the audit trail tamper-evident — an independent witness the ledger writer cannot
  impersonate. This is the platform's crown jewel.
- **🧪 Tests that can't lie to themselves.** Security properties are proven by re-introducing the
  bug (mutation testing) on live Postgres/NATS/TLS, not by mocks that share the code's assumptions.
- **📖 Honest by construction.** The docs say what runs, what's deferred, and what's still a claim.

## 🧭 Capabilities

OpenShield is architected as a **pipeline-native XDR + SOAR**, with each domain a detection lens over
the shared pipeline. Maturity is tracked candidly, and the *"what is not there yet"* column is the
point of the table rather than a footnote — percentages flatter, and a named gap does not.

The per-domain detection planes are broadly real and deep in several domains. What remains is
**operator surface**: everything below is driven by a CLI and an API, and the analyst UI is
deliberately last, after the platform it would display is built and tested.

| Domain | Maturity | What works today | What is not there yet |
|---|:---:|---|---|
| 🧬 **XDR** (umbrella) | 🟢 ~80% | Entity graph wired and populated by real producers (device⋈user); an entity-keyed alert stream fed by **every** domain; cross-domain correlation (distinct-domain window + ordered domain-sequence rules) materialised per entity and paging once; incident **timelines** carrying contributing alerts in detection order, each linked to evidence with an explicit resolved/unresolved/derived state; coordinated cross-domain response; per-entity risk aggregation. | Reading a timeline is view-audited, but there is no analyst UI to read it *in* — the CLI and API are the interface. |
| 🔐 **Zero Trust (ZTNA)** | 🟢 ~85% | Full hardware attestation chain (TPM quote → EK→AK activation → measured-boot PCR → continuous re-attestation), EK-cert anchoring, pre-auth enrolment tokens, DPoP-bound tokens, live JWKS refresh, RBAC tiers, and a dual-credential access proxy pairing device identity with user identity. | It brokers access; it does not yet **prevent bypass** (routing/firewall enforcement is a separate ticket). HTTP(S) only — no CONNECT/SOCKS, no split DNS. The endpoint-side client is built and **not yet shipped as a binary**. |
| 🗂️ **DLP** | 🟢 ~78% | Exact-data matching (single and multi-cell), document fingerprinting, exfil-channel awareness, keyword proximity, national IDs — all boundary-honoured, over signed indexes, with recursive archive extraction. Content-aware CASB blocks sensitive uploads to unsanctioned clouds. Clipboard is **mediated** on X11 (the engine owns the selection and decides each paste by destination); print jobs are aborted in the CUPS filter chain before they print. | Wayland clipboard stays observe-only — its protocol cannot identify a paste's destination. No OCR, no screenshot detection. |
| 🌐 **NIPS / NTPS** | 🟡 ~60% | Transparent TPROXY drops and splices L4 by destination IP, SNI or payload, and self-installs and self-heals its rules. Threat-intel IOC engine and content-signature engine, both hot-reloading from a local file or a remote URL. DNS preventive sinkhole with a transparent `:53` redirect and a bypass watchdog. Live DNS-query and SMTP-message inspection into the pipeline, including DNS-tunnelling scoring. | No full Suricata grammar, no HTTP/2 or QUIC, no JA3. SMTP is **captured and inspected, not filtered** — nothing is blocked on the mail path. |
| 📊 **SIEM** | 🟡 ~52% | Unified alert lifecycle (severity, status, dedup, ATT&CK mapping, durable notification dedup, pruned baselines). External-log ingest is live — CEF-over-syslog (UDP **and** reliable TCP/mutual-TLS), AWS CloudTrail, and Windows Event Forwarding XML — with field-level JSONB hunting over `GET /logs`. | Few formats relative to a mature SIEM; no saved searches; no cross-vendor field normalisation. |
| 🖥️ **HIPS** | 🟢 ~85% | Inline exec **prevention** on a live kernel: static deny-list/whitelist plus default-deny whitelisting, with the verdict coming from the **full pipeline** over a parser-free IPC bridge. FIM (baseline, real-time, signed, delete-aware), ransomware canaries, memory-injection detection, a trusted-identity critical-process guard with pid-reuse revalidation. A `CONTAIN` response-intent makes an entity's next exec kernel-refused. | No eBPF/LSM real-time hooks, no JIT W+X allowlist, no per-process ransomware attribution. |
| 🤖 **SOAR** | 🟢 ~95% | Correlation runs on a clock (leader-only). Incidents carry a forward-only attributed lifecycle. A declarative **playbook engine** over a closed, non-actuating step registry runs first response automatically and resumes across a restart without repeating a step. Signed threat-intel feed ingest enriches incidents from observables the verified events already carry. Response time is measured (detection latency, MTTA, MTTR) — each reported with the population it excludes. Notifications route by kind and severity to named sinks. Approved intents are enacted against an external identity provider with four-eyes re-checked by the runner, and incidents sync bidirectionally with a ticketing system. | Escalation *timers* (routing shipped, schedules did not); no incident reopen; no backfill outside the correlation window. |

<sub>⛓️ **Crown jewel:** the forward-secure hash-chained ledger + external anchoring is real,
end-to-end, and the strongest asset — every domain above writes evidence into it.</sub>

## 🏗️ Architecture

**One pipeline, every signal.** Endpoint, network, and identity telemetry all flow through the same
stages. Detection and enforcement are kept strictly separate — an enforcer receives only a
*decision*, never which detector matched or why:

```mermaid
flowchart LR
  EP["🖥️ Endpoint<br/>files · processes · USB"] --> C
  NW["🌐 Network<br/>HTTP · DNS · SMTP"] --> C
  ID["🔐 Identity<br/>access · device posture"] --> C
  C{{"Classify<br/>sandboxed worker · no network"}} -->|"type + count + metadata only"| POL["Policy<br/>rules + risk context"]
  POL --> DEC["Decision<br/>closed, typed action set"]
  DEC --> ENF["Enforce<br/>alert · block · quarantine<br/>redirect · encrypt · kill"]
  ENF --> LED[("Audit<br/>tamper-evident ledger")]
  LED --> INC["Investigate<br/>incidents · cases"]
  INC --> RSP["Analyze &amp; respond<br/>UEBA · cross-domain correlation · playbooks"]
  RSP -.->|"risk + signed response intent<br/>(context, never commands)"| POL
  LED -.->|attest| WIT{{"External witness"}}
```

**A stable core, plug-in capability.** The pipeline's core — the dispatcher, the stages, the enforcer
contracts, and the ledger — stays fixed. New capability lands as a new event source, a new detector,
a new policy input, or one deliberate new action, never as a change to the core. That discipline is
what lets a single codebase span seven security domains instead of fragmenting into seven products.

**The full picture** — OpenShield runs detection-and-response at **three tiers that share one pipeline
and one evidence ledger**: on the **host** (file DLP, HIPS process control, device posture, local
enforcement, plus DNS-query and SMTP-message inspection), at the **network gateway** (inline DLP *as*
NIPS over HTTP, the DNS sinkhole, plus ZTNA access brokering), and in the **control plane** (SIEM correlation, XDR cross-domain incidents, SOAR response).
Users reach internal apps, file servers, and databases *through* the gateway — inspected and brokered.
The **host agent's monitoring and the gateway's network detections stream as signed events** into the
control plane, where SIEM/XDR correlate them (with external syslog as an additional feed); and the
control plane feeds risk and coordinated-response context back out to every enforcement point.

```mermaid
flowchart TB
  INET["🌍 Internet"]

  subgraph EP["🖥️ Endpoints — host detection &amp; response"]
    HOST["<b>Agent · Engine · sandboxed Worker</b><br/>Host DLP — files · USB<br/>HIPS — process · exec · behavioral<br/>Device posture · Zero-Trust signal<br/>local enforce — quarantine · encrypt · kill"]
  end

  subgraph NETP["🌐 Network data plane — Gateway"]
    GW["<b>Inline DLP + NIPS/NTPS</b> — HTTP · TLS-intercept · DNS sinkhole<br/><b>ZTNA access broker</b> — identity + device posture<br/>allow · block · redirect"]
  end

  subgraph INNER["🔒 Protected inner network"]
    subgraph RES["Internal resources"]
      APPS["🗄️ Web apps · file servers · databases"]
    end
    subgraph CP["Control plane"]
      BUS(["📨 Telemetry bus · mTLS"])
      SRV["<b>Fleet server</b><br/>SIEM — search · correlation · UEBA<br/>XDR — cross-domain incidents · timelines · entity risk<br/>SOAR — cases · notify · playbooks · metrics"]
      LED[("Fleet store +<br/>hash-chained audit ledger")]
      PKI["Provisioning · PKI<br/>enrollment · identity"]
      ANC["Anchor ·<br/>external witness"]
    end
  end

  OPS["👤 Analysts / operators<br/>SIEM · SOAR console"]

  subgraph EXT["🔌 External integrations"]
    IDP["Identity provider<br/>OIDC / SSO"]
    ITSM["ITSM · ticketing"]
    TI["Threat-intel feeds"]
    LOGS["Syslog · external logs"]
    RUN["Response runners<br/>subscribe to signed intent"]
  end

  %% data plane — user access
  HOST -->|"internet — direct"| INET
  HOST ==>|"access internal resources"| GW
  GW ==>|"inspected · brokered"| APPS
  OPS ==>|"ZTNA access"| GW

  %% management plane — signed events into the inner network (the SIEM/XDR feed)
  HOST <-->|"signed telemetry · mTLS"| GW
  GW <-->|"controlled ingress"| BUS
  BUS ==>|"host + network events → SIEM / XDR"| SRV
  SRV --> LED --> ANC
  GW -.->|"operator console · mTLS"| SRV

  %% identity / zero trust
  PKI -.->|"enrolls · issues identity"| HOST
  IDP -.->|"SSO · JWT"| GW
  LOGS -.->|"additional log sources"| SRV

  %% coordinated response — risk + signed response-intent back to every enforcement point
  SRV -.->|"risk · signed intent"| BUS
  BUS -.->|"typed context"| HOST
  BUS -.->|"typed context"| GW
  SRV -.->|"enrich"| TI
  SRV -.->|"signed intent"| RUN
  RUN -.->|"disable user"| IDP
  RUN -.->|"open ticket"| ITSM
```

<sub><i>Deployment topology. The gateway is the network boundary into the protected zone; dashed
edges are the coordinated-response path — signed risk and response intent flowing back to enforcement
points as context, never as commands. Every box shown is built and tested; the capability table above
names what is missing inside each one, and there is no analyst UI over any of it yet.</i></sub>

## 🧩 Components

OpenShield ships as focused, single-responsibility binaries (all Go, `cmd/`):

| Binary | Role |
|---|---|
| **`openshield-engine`** | The endpoint pipeline. Unprivileged, network-capable; watches directories via notify-mode fanotify, ingests DNS queries and SMTP messages, classifies via the worker, evaluates policy, decides, and appends to the ledger. |
| **`openshield-worker`** | The unprivileged, seccomp-hardened parser. Reads classify requests, opens files with its own credentials, classifies untrusted bytes — holds no network and no secrets. |
| **`openshield-gateway`** | The network data plane. TLS-intercepting proxy (inline DLP), ZTNA access broker, and the DNS sinkhole — each request classified in the sandboxed worker. |
| **`openshield-server`** | The fleet control plane. Ingests signed telemetry over NATS, persists the fleet aggregate, runs correlation/incidents and alert delivery. It coordinates and observes; it does not control. |
| **`openshield-fleet-agent`** | The fleet-facing endpoint half: generates a per-agent identity, enrolls, and publishes signed telemetry, heartbeats, and device posture. |
| **`openshield-agent`** | The privileged inline-enforcement agent (fanotify **permission** mode). Needs `CAP_SYS_ADMIN`. It refuses an **execution** inline — statically, or on a verdict from the engine's full pipeline. Inline blocking of a file **open** is designed and not wired. |
| **`openshield-provision`** | Issues the credentials the stack needs — enrolment tokens, client certificates, and the witness, posture and risk keypairs. Minimal provisioning for dev and small fleets — not a full PKI. |
| **`openshield-anchor`** | Witnesses the audit-ledger head and stores an external anchor. It attests to the head; it cannot append — a witness the ledger writer cannot impersonate. |
| **`openshieldctl`** | The operator CLI: query the ledger as an incident timeline, verify it (with an external witness for completeness), run the **backup and restore drill** — a restore is not finished until the ledger re-verifies — and build or verify a **signed release** against a pinned key. |
| **`openshield-dlp-index`** | Builds and **signs** the exact-data-matching and document-fingerprint indexes the worker loads. An index whose signature does not verify stops the worker rather than silently matching nothing. |
| **`openshield-fim-baseline`** | Produces the signed known-good manifest file-integrity monitoring compares against. |
| **`openshield-print-filter`** | The CUPS filter-chain half of print DLP. A non-zero exit aborts the job, so it is prevention — and it parses nothing: the job is classified in the sandboxed worker, and it **fails open** if the engine is unreachable. |

## 🚀 Getting started

**Requirements:** Go **1.26+**, Linux (fanotify), PostgreSQL, and NATS. Containers use **Podman**.

```bash
# Clone
git clone https://github.com/lucianoengel/openshield.git
cd openshield

# Build + verify everything: vet, tests (with -race), doc/claim checks, binaries,
# cross-compilation, and the integration suite against live Postgres and NATS.
# It is the full gate and it is not quick.
make all

# The fast loop while iterating
make quick

# Or just compile the binaries under cmd/
make build
```

**See the observe path run end-to-end** — drop a real file in a watched directory and watch it land
an `ALERT` in the forward-secure ledger:

```bash
make integration
```

Configuration is **typed and two-tier**. *Bootstrap* settings — the ones a process needs before it can
reach anything — come from the environment: `OPENSHIELD_DSN` (Postgres), `OPENSHIELD_WATCH_DIRS`
(directories the engine observes), `OPENSHIELD_ENFORCE` (opt in to post-decision enforcement;
**observe-only by default**). *Dynamic* settings are **database-authoritative** and change without a
restart; the environment does not override them, so a value an operator sets cannot be silently
countermanded by a stale unit file.

Every setting declares a kind, and a malformed value is refused when it is set rather than falling back
to a default — a typo that quietly disables a detector is the failure this exists to prevent. Ask a
running deployment what it is actually using with `openshield-server config`, which reads the database
rather than reprinting the defaults. See [`deploy/`](deploy) for compose and systemd examples.

## 🗺️ Roadmap

**Shipped since this section last described the future** — each of these was listed here as
upcoming and is now built, tested, and in the capability table above:

- 🧬 **XDR** — the unified entity graph, cross-domain correlation, incident timelines, coordinated
  response, and per-entity risk aggregation
- 🤖 **SOAR** — the playbook engine, signed threat-intel enrichment, the response-intent model,
  response metrics, notification routing, IdP enactment, and ITSM sync
- 🌐 **Network prevention** — transparent inline interception (TPROXY), the signature and
  threat-intel engines, and the DNS sinkhole
- 🔏 **Hardware-backed device attestation** — the full TPM chain, proven end-to-end against swtpm
- 🔐 **Zero-Trust device identity and posture binding**, composable compliance packs, the unified
  alert lifecycle, and analyst RBAC

**Now — the operator surface:**
- 🖼️ **The analyst UI**, deliberately last: the platform it displays had to exist first
- 📦 **Packaging and operability** — signed reproducible releases, backup/restore drills, and
  configuration that can be set and read back without editing a unit file

**Next — depth over breadth:**
- ⚙️ **Scale & resilience** — durable messaging, active-passive high availability
- 🌐 **Deeper network inspection** — Suricata-grammar rules, HTTP/2 and QUIC, JA3, SMTP *filtering*
  (today SMTP is inspected, not blocked)
- 🖥️ **Cross-platform agents** (Windows / macOS)
- 🔍 **Endpoint depth** — eBPF/LSM hooks, per-process ransomware attribution

<sub>The detailed engineering plan and design-decision records are maintained in
[`docs/architecture-roadmap.md`](docs/architecture-roadmap.md).</sub>

## 🔐 Security model & design principles

OpenShield's guarantees come from a small set of deliberate, documented constraints:

- **Closed, typed action set.** The control plane can never express an arbitrary command; actions
  carry no free-form parameters. This is what makes *"the server coordinates, it does not control"*
  architectural rather than aspirational.
- **Content isolation.** Sensitive content is parsed only inside a sandboxed, network-less worker;
  only type, count, and metadata ever cross the boundary — never the content itself.
- **Observe by default.** Enforcement is opt-in; out of the box the platform detects and audits
  rather than blocks.
- **Deliberate egress fail-open.** Inline network paths fail *to wire*, never fail the network
  closed — availability is a conscious, documented choice for egress.
- **Tamper-evident evidence.** The forward-secure, hash-chained ledger with external anchoring can be
  independently verified, not merely trusted.

See the [threat model](docs/threat-model.md) and [design-decision log](docs/decisions.md) for the
full rationale.

## 📚 Documentation

| Doc | What's in it |
|---|---|
| [Architecture roadmap](docs/architecture-roadmap.md) | Live capability status, the prioritized plan, and the architecture-decision records |
| [Design decisions](docs/decisions.md) | The architecture-decision log behind the codebase |
| [Threat model](docs/threat-model.md) | Assets, adversaries, trust boundaries |
| [Architecture proposal](docs/architecture-proposal.md) | The original pipeline thesis |
| [DPIA template](docs/dpia-template.md) | Data-protection impact assessment scaffold |
| [Operator runbook](docs/runbook.md) | Running the stack: deployment, backup drills, verification |
| [Unwired-feature audit](docs/unwired-audit.md) | A running log of code that was built, tested, and reachable by nothing — and the ways a green test can mean nothing |

## 🤝 Contributing

Contributions are welcome. A few house rules that keep the project honest:

- **Keep pull requests focused** — one self-contained change at a time.
- **Tests must drive the real runtime path**, never a mock built from the code's own assumptions.
  For every security property, add an adversarial test that re-introduces the bug and proves the test
  catches it.
- **Respect the stable core.** New capability should land as a new event source, detector, policy
  input, or action — not as a change to the core pipeline.
- Run `make all` (vet, tests with `-race`, doc/claim checks, build, cross-compile, integration)
  before opening a PR. `make quick` is the loop to run in between.

Use [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `refactor:`, …).

## 📄 License

Licensed under the **[Apache License 2.0](LICENSE)**.

<div align="center"><sub>Built in the open · <code>github.com/lucianoengel/openshield</code></sub></div>
