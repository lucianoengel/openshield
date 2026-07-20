# Decision Register

**This file is the single source of truth for D-numbers.** Every other document references
decisions *by number* rather than restating them. If a decision changes, it changes here first.

Why this exists: D1-D23 were previously scattered across six documents, each paraphrasing them
slightly differently. [`brief.md`](brief.md) drifted out of sync twice as a result — still describing a
Rust agent after D8 had made the project all-Go. Restatement is what rots; references don't.

Rationale lives in the research reports, which are **append-only historical records** and are
never rewritten: [`research-scouting-r1.md`](research-scouting-r1.md) (D1-D9) and
[`research-review-r1.md`](research-review-r1.md) (D10-D23, four adversarial reviewers).

Status: **firm** = settled, changing it is a project pivot · **open** = awaiting evidence or
an owner call · **scoped** = settled but with a named condition that could narrow it.

---

## Scope and phasing

| # | Decision | Status |
|---|---|---|
| **D1** | **Phase 1 is observe-and-audit only.** Decisions are recorded, not enforced. Enforcement lands in Phase 2 once the classifier's real false-positive rate is known. DLP has no cheap partial-credit MVP: false negatives leak, false positives block legitimate work. | firm |
| **D2** | **No clipboard events.** Wayland mediates the clipboard through the compositor and hands data only to the focused client — system-wide observation is *architecturally prevented*, not merely hard. Documented as a platform gap. | firm |
| **D7** | **Keep the core small.** Prior OSS DLP died of maintenance economics, not bad detection (MyDLP acquired, OpenDLP abandoned, Apache Metron retired to the Attic). Ambition is the failure mode. | firm |
| **D9** | **Windows/macOS via GitHub Actions runners, not local VMs.** Windows: a VM solves *dev* (test-signing loads unsigned drivers); shipping needs an EV cert (~$300-600/yr) + Microsoft attestation. macOS: Apple's EULA permits virtualisation only on Apple hardware, and Endpoint Security needs an entitlement Apple grants selectively. Not an infrastructure problem. | firm |

## Language and engine

| # | Decision | Status |
|---|---|---|
| **D8** | **Single language: all-Go** (and **pure** Go — T-005 confirmed `x/sys/unix` covers fanotify; event parsing is hand-rolled over a stable ABI, no CGO. Review finding A3 closed.), superseding the brief's Rust-agent/Go-backend split. One language ⇒ one shared policy engine ⇒ the cross-runtime parity risk is *deleted rather than solved*. Chosen over Rust because the owner does not write code: agent-written Go converges in fewer compile-fix cycles and is reviewable by a non-coding owner — the only real oversight mechanism here. | firm |
| **D19** | ~~D8 is scoped~~ — **RESOLVED 2026-07-20 by measurement, D8 stands unmodified.** Worst-case responder latency 532µs (typical 1-3µs) at 2 cores under 256 MB/s allocation and 10× realistic event rate. GC is not the risk; unbounded stalls are, and those are a design problem the fail-open watchdog addresses (D17/D18, T-011) — not a language problem. Evidence: [`spike-t002-gc-pause.md`](spike-t002-gc-pause.md). | firm |
| **D6** | *(collapsed)* Policy IR — dissolved by D8. OPA/Rego runs natively in Go; no CEL, no WASM, no custom IR. CEL was the trap: an official cross-language conformance suite exists but nobody runs it against the Rust implementation. WASM remains relevant only for sandboxing untrusted Hub packs (Phase 3+). | firm |

## Detection and enforcement

| # | Decision | Status |
|---|---|---|
| **D3** | **fanotify is the primary hook**, with **fail-open engineered from the first commit** (self-PID bypass, response-timeout watchdog, safe teardown). The kernel does not fail open for you — blocked processes park in `TASK_UNINTERRUPTIBLE` and can hang the machine. Blocks open/read/exec; **not** rename or unlink. | firm |
| **D4** | **Decision carries confidence, not certainty.** Classification is noisy by nature (Presidio ~22.7% precision on person names). Policy must consume confidence and thresholds, never a clean boolean. | firm |
| **D5** | **Endpoint classification is patterns and deny-lists only.** No spaCy/NER on the agent — Microsoft deploys Presidio server-side because the NER path is not endpoint-viable. | firm |
| **D14** | **The Enforcer action set is CLOSED and TYPED** (Block / Alert / Quarantine-local / Encrypt-local). An open action framework lets a compromised control plane express "upload file to URL", indistinguishable from normal telemetry. This is what makes "the server coordinates, does not control" architectural rather than aspirational. | firm |
| **D17** | **Fail-open is per-policy, and is itself a bypass.** Make classification slow (huge file, zip bomb, ReDoS, load) and every Block becomes an Allow — the starvation trick used against WAFs. Every timeout-allow emits a high-severity audit event; scan budgets capped; timeout *rate* is its own signal. | firm |
| **D18** | **Phase 1 exercises the fail-open watchdog for real** (injected delay, assert auto-`FAN_ALLOW`), even though verdicts stay always-allow. USB enforcement does *not* test this contract — attach-time allow/deny has no blocked process and no race. | firm |
| **D16** | **Tamper-detection, never tamper-prevention.** Heartbeat / dead-man's-switch / "agent last seen". Anyone with root defeats a host agent; there is no fix that doesn't require distrusting the OS the agent runs on. | firm |

## Privacy and data handling

| # | Decision | Status |
|---|---|---|
| **D10** | **No exact-match hashing of low-entropy PII.** SSN and Brazilian CPF ~10⁹, cards ~10⁷ after BIN+Luhn, DOB ~36.5k — all brute-forceable, and **salting does not fix it**. Worse, cross-endpoint matching needs a deterministic key, which would have to live on every agent. Use format+checksum detection locally; transmit **type + confidence + count** only. Keyed EDM for high-entropy composite records, key server-side only. | firm |
| **D11** | **Embeddings and fuzzy fingerprints are content-equivalent.** Similarity-preserving hashes leak structure by construction; vec2text recovers ~92% of 32-token inputs exactly. Encrypted, access-controlled, **never distributed through the Hub**. Not a de-identification technique. | firm |
| **D12** | **Audit ledger = Postgres hash chain + forward integrity + external anchoring.** JetStream is a **bus only** — bounded retention is not a system of record. Key-evolving schemes so a post-compromise attacker cannot rewrite pre-compromise entries. Claim **"tamper-evident with forward-integrity between anchors"**; never "tamper-proof", which is unachievable in a single self-hosted trust domain. | firm |
| **D20** | **Privacy-law features are Phase-1 architecture, not later additions:** enforced retention with automatic purge, purpose tagging at schema level, exclusion lists as a first-class policy primitive, pseudonymisation by default, audit trail of who *viewed* an investigation, four-eyes before HR-visible outcomes, a shipped DPIA template. GDPR Art. 35 makes a DPIA effectively mandatory; German works councils hold an **absolute veto** (BetrVG §87(1)(6)). | firm |
| **D23** | **UEBA supports both modes, gated.** Self-baseline computed locally, on by default. Peer-baseline is an **optional server-side Analytics module, off by default**, with its own consent/DPIA gate. Resolves the brief's silent contradiction between "Peer Analysis" and "the server coordinates, does not compute". Phase-1 cost is one field: a stable pseudonymous user ID. | firm |

## Runtime architecture

| # | Decision | Status |
|---|---|---|
| **D24** | **The endpoint pipeline is in-process and synchronous; NATS is the agent↔control-plane boundary only.** The brief names NATS as "the message bus" and says components communicate exclusively through events — read literally on the endpoint, that puts a broker inside the fanotify permission window, where [T-002](spike-t002-gc-pause.md) measured a 1-3µs typical / 532µs worst-case budget with a real process blocked in `TASK_UNINTERRUPTIBLE`. A broker round trip does not fit, and local-first evaluation (D1) means it should not have to. Both mechanisms are "the event bus" in the brief's language; only the second is NATS. Enforced by CI: `internal/core` may not import a broker (`scripts/check-core-deps.sh`). | firm |
| **D25** | **Per-stage deadlines are owned by the dispatcher, not the stage.** A stage that sets its own deadline can set it to infinity, and an unbounded stage is the mechanism by which the responder hangs a machine. **Honest limit:** Go cannot preempt an uncooperative function, so the deadline bounds the dispatcher's *wait* and a pathological stage's goroutine may outlive it. That is why T-011's fail-open watchdog — which answers the kernel regardless of what the pipeline is doing — is an independent mechanism rather than a consequence of this one. | firm |

| **D26** | **The zero-core-change claim is narrowed, and the CI fitness test is necessary but not sufficient.** Capabilities of the same *shape* as existing ones need no core change; a new *shape* of data flow needs a small one. Demonstrated by [T-004](design-t004-peer-ueba.md), which also produced a worked example of the fitness test being gameable: letting Policy query the analytics store directly passes CI with zero core diffs while destroying the stage isolation the test exists to protect. Green CI is not evidence the architecture held. | firm |
| **D27** | **`Decision` carries a `context_version`.** Added before any consumer existed, because replay cannot reproduce a Decision without knowing which enrichment context applied, and retrofitting a field into a hash-chained ledger (T-009) means a migration and a break in chain continuity. Empty in Phase 1. | firm |

## Security of the platform itself

| # | Decision | Status |
|---|---|---|
| **D13** | **Privilege-split agent; untrusted parsing in an unprivileged sandboxed worker.** Root + `CAP_SYS_ADMIN` + parsing attacker-controlled PDFs is the textbook way to make an org *less* secure — cf. ClamAV **CVE-2025-20260**, a PDF-parser heap overflow to RCE. The privileged process never decodes attacker-controlled bytes. Decompression-bomb limits before any parser runs. | firm |
| **D15** | **Hub uses ed25519 per-author signing**, keys pinned at install, metadata cached with expiry and **fail-closed when stale**. Content-hash-against-index (CrowdSec's model) answers "did I download what the index said", not "who may publish" — and packs execute at high privilege on every endpoint, making this a fleet-wide root-equivalent supply chain. **Offline revocation is fundamentally unsolved**: the propagation window equals the sync interval. Document it; do not imply otherwise. | firm (design deferred) |

## Project and governance

| # | Decision | Status |
|---|---|---|
| **D21** | **Design for open-core separability now.** Keep managed Hub, compliance packs and multi-tenant control plane cleanly separable. Retrofitting the boundary later is expensive; a CI import test costs one ticket. The sustainability model itself is deferred explicitly. | firm |
| **D22** | **Disclose AI authorship.** Owner signs commits and takes responsibility; AI authorship declared via commit trailers and `CONTRIBUTING.md`. Note the open question this raises: AI-generated code may not be copyrightable absent human authorship in several jurisdictions, which would undercut the Apache-2.0 patent-grant rationale. | firm |
| **—** | **Licence: Apache-2.0.** Permissive as the owner requested; chosen over MIT for the explicit patent grant, which matters in a patent-dense field. No field-of-use restriction, so nothing prevents surveillance use — a conscious call, see [`../ETHICS.md`](../ETHICS.md). | firm |

---

## Superseded

- **The brief's Rust agent + Go backend** → D8 (all-Go).
- **"Prefer storing hashes/fingerprints" as a privacy control** → D10/D11. False as written.
- **"Tamper-proof audit logs"** → D12. Unachievable in one self-hosted trust domain.
- **Implied prevention of exfiltration** → D16 and [`threat-model.md`](threat-model.md).
- **`BrowserUploadStarted` in Phase 1** → cut 2026-07-20; needs a browser extension or TLS
  proxy, not a kernel hook. Deferred to Phase 2.

## Known open questions

- **A2 shape questions** — Data Discovery is a catalog and Lineage is a graph; neither has a
  home in the frozen pipeline. T-004 tests only the UEBA sliver of this.
- Whether the fitness test can ever be strong enough: adding an S3 connector is isomorphic to
  what exists and proves little; the paper design of peer-UEBA (T-004) is the real test.
