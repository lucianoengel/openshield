# OpenShield — Round-1 Scouting

**Date:** 2026-07-20 · **Case:** openshield · **Status:** decisions proposed, none locked

Three parallel scouts: Linux blocking hooks, policy IR (Rust/Go parity), prior art + the
open-source DLP graveyard. Source URLs are in the per-topic sections.

---

## Headline: the brief's riskiest assumption is real-time blocking in Phase 1

Two independent scouts converged on the same conclusion from opposite directions, and neither
was asked to look for it:

- **Prior art:** DLP has no cheap "observe and alert" MVP the way EDR does. osquery, Wazuh,
  Velociraptor and Falco succeeded partly because a missed event is a *gap*, not active harm.
  DLP's blocking MVP has no partial credit: false negatives leak data, false positives block
  legitimate work. The scout's own recommendation, unprompted: ship observe/audit-only first.
- **Kernel:** the mechanism that makes blocking possible (fanotify permission events) is also
  the one that can **hang the whole machine** if the agent stalls or dies. Documented Red Hat
  and SUSE production incidents; processes park in `TASK_UNINTERRUPTIBLE` awaiting a verdict
  the agent never sends.

**Proposed:** Phase 1 ships **observe + audit only**. The pipeline runs end to end —
Event → Classification → Policy → Decision → Audit → Investigation — but the Decision is
*recorded*, not enforced. Enforcement lands in Phase 2 once the classifier's false-positive
rate is known from real data on the owner's own fleet.

This costs little architecturally: the pipeline is unchanged, and `Enforce` is one stage that
gets a real implementation later. It buys a Phase 1 that cannot brick the machine it runs on —
which matters more than usual, because the forcing function is *self-use*.

Counter-argument, stated fairly: a DSP that never blocks is arguably not a DSP, and shipping
enforcement late risks discovering the enforcement interface is wrong. Mitigation is to design
and type the Enforcer interface in Phase 1 and ship one trivial real enforcer (USB, which is
the safest and best-trodden) rather than deferring the whole concept.

---

## 1. Linux blocking hooks

| Mechanism | Blocks? | Floor | Privilege | MVP verdict |
|---|---|---|---|---|
| fanotify `FAN_*_PERM` | Yes — open/read/exec | 2.6.37+ (exec 5.0) | CAP_SYS_ADMIN | Primary blocking hook |
| eBPF tracepoints/kprobes | **No** — observe only | 4.x+ | CAP_BPF | Telemetry only |
| BPF-LSM | Yes — per-hook deny | 5.7+ **and** boot-enabled | CAP_SYS_ADMIN | v2 — not default on many distros |
| Landlock | Self-restriction only | 5.13+ | unprivileged | Not usable to police *other* processes |
| USB `authorized_default` | Yes | modern | root | Usable now (USBGuard model) |
| Clipboard — X11 | Observe, hacky | — | session | Legacy only |
| Clipboard — **Wayland** | **No** | — | — | **Architecturally prevented** |
| Browser upload | Partial | — | — | Extension first; MITM heavier |

**Consequences for the design:**
- fanotify blocks `open`/`read`/`exec` but **not** `rename` or `unlink` — those are notify-only.
  Phase 1 cannot honestly claim to block a rename-then-move exfil path at that layer.
- **Fail-open is a first-commit requirement, not a later hardening task.** Three specific
  mechanisms: self-PID bypass (else the agent deadlocks on its own I/O), a response-timeout
  watchdog that auto-`FAN_ALLOW`s, and careful group teardown. The kernel does not do this
  for you.
- **Clipboard events come off the MVP list.** Wayland mediates clipboard through the
  compositor and hands data only to the focused client. Not awkward — prevented. Record as a
  documented platform gap; do not carry `ClipboardCopied` in the Phase 1 event list.

## 2. Policy IR — Rust/Go parity

| Option | Parity risk | Rust maturity | Verdict |
|---|---|---|---|
| CEL (cel-go + cel-rust) | **High** | community-grade | **Avoid for now** |
| Rego via **regorus** | Medium-low | production (Azure Confidential Containers, GA) | **Recommended** |
| Rego → WASM (`opa build -t wasm`) | Low | runtime-only | Strong alt; narrower builtins |
| Policy → WASM (own compiler) | **Lowest** | runtime-only | Best long-term, most upfront work |
| Custom bytecode | Lowest | you own everything | Only if policy language stays narrow |

**CEL is the trap.** It looks the most de-risked — clean syntax, `cel-go` proven in Kubernetes,
and an official cross-language conformance suite. But that suite does not appear to be run
against the Rust implementation by anyone, and `cel-rust` is a community project, not Google's.
The asset that makes CEL attractive is aspirational on the Rust side.

**regorus** is the only candidate with production use *and* conformance evidence (claims to
pass OPA's v1.2.0 suite). **Caveat: that claim is self-reported from the project README —
verify it independently before committing.** Its ongoing tax is "barring a few builtins":
enumerate the builtins our policies use, pin OPA and regorus versions together, re-diff on
every upgrade. Nothing auto-gates drift.

**The structural alternative:** compiling policy to WASM and running the *same bytecode* under
wasmtime on both sides eliminates reimplementation risk **by construction** rather than by
testing — there is no second interpreter to diverge. Costs a compiler. Given that cross-runtime
parity is the single biggest correctness risk in the design, "eliminate by construction" may
justify the price. **Open decision — do not lock without weighing actual Phase 1 policies**,
since choosing Rego means Rego's semantics constrain policy expressiveness for a decade.

## 3. Prior art & the graveyard

**Why the predecessors died — and it is not what the brief assumes:**
- **MyDLP** — acquired by Comodo 2014, free edition pulled. Killed by acquisition.
- **OpenDLP** — last release 2012. Pure maintenance abandonment; one or two unpaid maintainers
  could not survive OS churn.
- **Apache Metron** — retired to the Attic 2020. An ambitious multi-stage pipeline that got too
  heavy for volunteers once corporate sponsorship evaporated. The closest cautionary tale to
  *this* architecture.

Common thread: they died of **maintenance economics and absent commercial models**, not of bad
detection. The endpoint-agent-everywhere model requires sustained paid engineering to track
OS/kernel churn. For a solo unpaid builder this is the central risk, and it argues directly for
**Linux-only, narrow scope, and few moving parts** — the Metron lesson is that architectural
ambition itself can be the thing that kills a volunteer project.

**Classification accuracy is worse than the brief assumes.** Presidio benchmarks show ~22.7%
precision on person-name detection in business documents — roughly 3 in 4 flags wrong on that
entity type. Consequences:
- The Policy engine must treat Classification output as **noisy**: confidence scores,
  thresholds, human-in-loop — never a clean boolean. This should shape the `Decision` contract.
- Presidio's spaCy NER path is **not endpoint-viable**; Microsoft deploys it server-side. On a
  constrained agent, use pattern/deny-list recognizers only, or accept a server round-trip
  (which fights the privacy-first principle).
- This vindicates observe-only Phase 1: enforcing on a classifier with that FP rate would make
  the tool hostile to its own user.

**CrowdSec confirms the decision-separation bet.** Its `Decision` object carries
`{id, scenario, scope, type, value, origin, duration, action}` and deliberately **no reason,
no log line, no scenario internals**. Bouncers hold zero detection logic. That discipline is
what let 15+ independently-written bouncers exist. Direct model for our Enforcer interface.

Its **Hub** trusts by **content hash against a centrally-served index over HTTPS**, not
per-item author signing — worth knowing, since our brief implies stronger supply-chain trust
than CrowdSec actually provides. It degrades gracefully offline: local scenarios, decisions and
bouncers all work; only the shared CTI feed needs connectivity. Good air-gap precedent.

Complaints worth heeding: steep onboarding, "more moving parts than the problem needs", and
5-10x fail2ban CPU for simple cases. All three are failure modes this brief is prone to.

---

## Recommended decisions

| # | Decision | Confidence |
|---|---|---|
| D1 | Phase 1 = **observe + audit only**; enforcement Phase 2. Ship one trivial USB enforcer to prove the interface. | High |
| D2 | **Drop clipboard events** from MVP; document as a Wayland platform gap. | High |
| D3 | fanotify as primary hook; **fail-open engineered from commit one** (self-PID bypass, timeout watchdog, safe teardown). | High |
| D4 | `Decision` contract carries confidence, not certainty; Policy tolerates noisy Classification. | High |
| D5 | Classification on endpoint = patterns/deny-lists only. No spaCy NER on the agent. | Medium-high |
| D6 | Policy IR: **regorus**, pending independent verification of its conformance claim — *or* policy→WASM if we accept a compiler to kill parity risk by construction. | **Open — owner call** |
| D7 | Keep the core deliberately small (Metron lesson). Resist breadth. | High |

## Open questions for the owner
1. **D6** — regorus (cheaper, ongoing parity tax) vs WASM-as-IR (dearer, parity risk gone by
   construction)? I lean WASM-as-IR given self-use means few policies and a long horizon, but
   it is a real cost and the call is yours.
2. Does observe-only Phase 1 satisfy what you want from this as a portfolio artifact, or does
   "it actually blocks things" matter to you enough to take the risk earlier?
3. GitHub repo location, and hours/week.

---

## Addendum — decisions and measurements, 2026-07-20 (same day)

### D8 — Single language: **all-Go** (supersedes the brief's Rust agent + Go backend)

The brief's two-language split is the *sole* cause of the cross-runtime parity risk that
dominated D6. One language ⇒ one shared policy engine ⇒ no parity problem at all.

Chosen Go over Rust because the owner **does not write code** — work is agent-driven and
owner-reviewed. That voids the fluency argument (the main point for Rust) and promotes two
others: agent-written Go converges in fewer compile-fix cycles, and Go is far more reviewable
by a non-coding owner, which is the only real oversight mechanism on this project.

Supporting: nearly every platform dependency is Go-native (NATS, OPA, `cilium/ebpf`, mature
gRPC/OTel); Velociraptor proves Go endpoint agents work in security at scale; Go
cross-compiles trivially to Windows/macOS, keeping portability cheap.

**Correction to an earlier claim in this report's framing:** "memory safety favours Rust" was
overstated — Go is memory-safe too; the comparison was never Rust vs C. Rust's genuine edges
are no-GC determinism and compile-time data-race prevention, both narrower. The real
counter-argument for Rust is that a stricter compiler is a better guardrail for AI-written
code — acknowledged, and outweighed by velocity and reviewability.

**D6 collapses:** one shared Go policy engine on OPA natively. No IR question, no WASM for
correctness. WASM stays available later solely to sandbox untrusted Hub policy packs (Phase 3+).

### D9 — Windows/macOS: CI runners, not local VMs

- **Podman cannot grant KVM.** Containers share the host kernel; `/dev/kvm` is ACL'd to
  `luciano` only, and a rootless container running as `coder` still gets EPERM. `--device`
  does not confer access the host user lacks. Verified.
- **Windows** — a VM *does* solve driver development (free 90-day eval images; test-signing
  mode loads unsigned minifilters). It does **not** solve distribution: that needs an EV
  code-signing cert (~$300-600/yr + identity vetting) and Microsoft attestation signing.
  Dev is a permissions fix; shipping is a purchase.
- **macOS** — a VM cannot fix it. Apple's EULA permits virtualising macOS only on
  Apple-branded hardware (this is Linux/AMD), and the Endpoint Security framework needs the
  `com.apple.developer.endpoint-security.client` entitlement, which requires Developer Program
  membership and an application Apple can decline. Gated by Apple, not by infrastructure.
- **Therefore:** use free GitHub Actions `windows-latest`/`macos-latest` runners (macOS runners
  are real Apple hardware, so legitimate) for cross-platform **build + unit test**. Keeps the
  portability claim honest with zero local infra. Won't load kernel drivers in CI.
- **No host access requested now** — not needed for Phase 1. Defer until Phase 2.

### M1 — Measured: fanotify capability in **this dev sandbox** (2026-07-20)

> **Scope warning (added after owner challenge).** Everything in M1/R1 is about the `coder`
> dev sandbox, **not** about the product. A deployed OpenShield agent is a systemd service
> running as root with `CAP_SYS_ADMIN` and `CAP_DAC_READ_SEARCH` on a machine whose owner
> installed it deliberately. **No measurement below constrains the architecture.** It only
> answers "what can we build and run here without asking for a host change." If the dev loop
> needs a capability, the fix is to ask for it — never to redesign the product around a
> sandbox limit. An earlier draft of this report let that distinction blur; this note corrects
> it. (D1 observe-only came from the research findings above, not from these limits — the
> overlap is coincidence.)


Empirical, on host as `coder` and in rootless Podman with `--cap-add SYS_ADMIN`:

| fanotify mode | host (`coder`) | rootless Podman +SYS_ADMIN |
|---|---|---|
| `FAN_CLASS_NOTIF` | EPERM | EPERM |
| `FAN_CLASS_NOTIF｜FAN_REPORT_FID` | **OK** | **OK** |
| `FAN_CLASS_CONTENT` (blocking) | EPERM | EPERM |
| `FAN_CLASS_PRE_CONTENT` (blocking) | EPERM | EPERM |

**Conclusions:**
1. Blocking modes need real init-userns `CAP_SYS_ADMIN`. **Rootless Podman does not help** —
   userns `CAP_SYS_ADMIN` is not the same capability. Same root cause as the KVM denial.
2. **Unprivileged observe (`FAN_REPORT_FID`) works today**, no caps, no container, no host
   change. This is exactly what observe-only Phase 1 (D1) requires — so **Phase 1 needs no
   privilege escalation at all.** Convergence with D1 is fortunate, not planned.
3. Phase 2 blocking will need host-side `CAP_SYS_ADMIN` (or a Linux VM, which needs KVM —
   also a host change). One combined ask, deferred until Phase 2 justifies it.

**R1 — dev-loop question only (demoted from "open risk").** Unprivileged fanotify reports
*file handles*, not fds; resolving one to read content generally needs `CAP_DAC_READ_SEARCH`.
In **production this is a non-issue** — the agent has that capability. It matters only for how
far the local test loop gets before we need a host change. If it bites: ask for the capability
(or use a VM). **Not a design input.**

## Not yet researched (deliberately deferred)
Agent operability patterns from Wazuh/osquery (install, upgrade, fleet management) — a
build-time question, not a decision gate. Full classification-engine survey beyond Presidio.
