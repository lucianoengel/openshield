# OpenShield — Phase 1 Implementation Plan

> **RESUME STATE (2026-07-20).** Session was relaunched to fix an Ultraplan handoff failure:
> the harness captured git state at launch, when `~/workspace/openshield` was still an empty
> non-repo, so `git bundle --all` kept failing even after the repo was created mid-session.
> Repo is now valid — branch `master`, commit `81d46cc`, six files (intake, case log, both
> reports, two empty ledgers).
>
> **On resume:** this plan is ready. Next action is to hand it to Ultraplan (call
> ExitPlanMode; the user redirects it), or — if skipping the cloud pass — write these 15
> tickets via
> `python3 ~/workspace/homelab/bootstrap/scripts/tickets.py add --case ~/workspace/openshield ...`
> and start M0.
>
> **Full context lives on disk**, not in conversation: `~/workspace/openshield/intake.md`
> (brief, threat model, reworded privacy claim), `reports/scouting-r1.md` (D1-D9),
> `reports/review-r1.md` (D10-D23), `case.md` (working log). The lab memory graph key
> `case:openshield` carries the decision summary. **Read those before changing this plan** —
> the reasoning behind every D-number is there, and re-deriving it wastes a research round.

## Context

OpenShield is a greenfield open-source Data Security Platform. The bet: a fixed pipeline
(Event → Classification → Policy → Decision → Enforcement → Audit) absorbs a decade of
capabilities by only adding plugins. DLP is capability #1, not the product.

Two rounds of work preceded this plan, both in `~/workspace/openshield/reports/`:
- **`scouting-r1.md`** — research (D1-D9). Established Linux-first, observe-only Phase 1,
  no clipboard events, all-Go, GitHub Actions for cross-platform CI.
- **`review-r1.md`** — 4 adversarial reviewers (D10-D23). Verdict: *the pipeline architecture
  largely survives; the brief's stated principles do not.* The privacy model, the
  "tamper-proof" claim, and the implied prevention guarantee were all found unachievable as
  written and have been reworded in `intake.md`.

**Why we stop analysing now.** Two review rounds on zero code is already generous. The research
itself found that prior OSS DLP died of ambition outrunning delivery (MyDLP, OpenDLP, Apache
Metron). A third review round would be that failure mode. Everything still open is *empirical*
(does Go's GC jitter break the fanotify responder?) or a matter of taste — neither is
answerable by more review. The remaining risk is retired by building.

**Intended outcome of Phase 1:** a walking skeleton where one real event flows the whole
pipeline and lands in a tamper-evident audit row, with the architectural properties that are
expensive to retrofit (process boundaries, closed action set, schema shape) correct from the
first commit — and the properties that are cheap to add later (seccomp hardening, OTel, UI)
deliberately deferred.

## Immediate next action (owner-approved 2026-07-20)

Execute **T-001 now**, before anything else: create `github.com/lucianoengel/openshield`
(public, Apache-2.0) and push the existing local commit `81d46cc`, so the decision record —
intake, threat model, both research/review reports — is public from the first commit.

Ultraplan handoff failed three times with `git bundle --all` reporting no repository, despite a
valid local repo. Cause is not the missing remote (bundling is local); most likely the harness's
launch-time git state, captured when the case dir was still empty. **Not worth further
debugging** — the plan is complete and does not depend on the cloud refinement pass.

## Plan review round 1 — applied 2026-07-20

An adversarial review of *this plan* (not the architecture) found that the plan could have been
completed 100% while failing to deliver the project's headline claims. All fixes applied;
tickets now **21, ~89 agent-hours** (was 15 / ~54h — the old number was an underestimate, not a
scope increase).

**Gaps closed — decisions that were recorded but had no implementing ticket:**
- **D16 tamper-detection** → new **T-018** (heartbeat / dead-man's-switch / "agent last seen").
  Without it the README's honest claim — *detection, not prevention* — was unbacked.
- **D12/B3 external anchoring** → new **T-019**. T-009 did local forward-integrity only and
  hand-waved anchoring to an M2 ticket that did not exist.
- **A6 agent identity/enrollment** → new **T-017**. The agent had no identity at all; review had
  explicitly called a shared fleet secret a fleet-wide risk.
- **D1 USB enforcer** → new **T-020**. D1 said "ship one trivial USB enforcer to prove the
  interface"; the first ticket pass dropped it silently.
- **D21 open-core separability** → new **T-021** (import-boundary CI test).
- **L1 remainder** (notice mechanism, four-eyes gate, DPIA template) folded into **T-013**;
  **L2** (Apache-2.0 §7 deployer-liability note) and **L5** (ETHICS.md) into **T-001**.

**Silent scope cut, now recorded:** `BrowserUploadStarted` is **cut from Phase 1** and noted in
`intake.md` — it needs a browser extension or TLS-terminating proxy, not a kernel hook. Recorded
as a decision rather than left to drift out of the ticket list, which is how it was first lost.

**Dependency fixes:** T-015 was not gated on T-007/T-008 — the dogfood milestone did not require
the classifier or policy stages it exists to exercise. T-007 now depends on T-003 (it emits the
schema's shape). T-014 now depends on T-008/T-009 (needs a core to diff against).

**Sequencing fix:** T-003 (schema) is finalised before T-005 characterises what fanotify actually
delivers. Rather than reorder, T-003 gets the same **"revise now if wrong"** licence as T-004.

**New cheap gate:** **T-016** — a throwaway wiring proof (stub classifier + flat-file sink, one
event end to end) before committing ~13h to the real classifier and cryptographic ledger.

**Acceptance criteria made testable.** Negative properties ("never parses untrusted bytes",
"transmits no content") were unfalsifiable prose. Now: an import allowlist enforced by
`go list -deps` in CI plus a syscall audit (T-006); wire-byte grep for seed substrings across
PII fixtures (T-007); a CI denylist grep for `tamper-proof`/`prevents`/`guarantee` in docs
(T-001); quantified CPU/RSS ceilings and a latency benchmark (T-015).

**Estimates corrected:** T-006 5→8h, T-009 5→8h, T-013 5→8h, T-012 3→5h, T-007 4→5h, T-015 4→6h.
T-015's hours also wrap an unavoidable ~1-week calendar soak — a units distinction, not a
magnitude one.

**Explicitly deferred without a ticket** (recorded so it is a decision, not an oversight):
D15/C2 Hub signing design, and A2's Data Discovery / Lineage / Analytics shape questions.
T-004 covers only the UEBA sliver of A2.

## Sequencing principle

Ordered by **risk retired per hour**, not by dependency convenience:
1. Decisions that are hard to reverse (schema, contracts, process boundaries) come first.
2. Measurements that could invalidate a decision come before code that depends on it.
3. The paper test of the 10-year claim happens before the code that assumes it.

## Milestones

### M0 — Foundations (retire the reversible-decision risk)

**T-001 · Repo skeleton + governance** — `est 2h`
**Settled 2026-07-20: `github.com/lucianoengel/openshield`, PUBLIC, Apache-2.0.** The local repo
already exists with commit `81d46cc` (intake, case log, both reports) — T-001 creates the
remote and pushes that history, so the decision record is public from the first commit. Public
also unlocks free `windows-latest`/`macos-latest` Actions runners (D9).

Go module layout: `cmd/`, `internal/core/`, `internal/agent/`, `internal/connectors/`,
`internal/enforcers/`. Governance docs are day-one, not later:
- `LICENSE` (Apache-2.0), `SECURITY.md` with a **solo-meetable SLA** ("acknowledgement within
  5 business days, no fix-time guarantee" — an honest slow SLA beats a missed aspirational one)
- `CONTRIBUTING.md` disclosing AI authorship (owner signs commits, `Generated-by:` trailers)
- `README.md` using the **honest claims** from `intake.md` § Threat model — visibility and
  friction for careless insiders, tamper-*evident* trail. Explicitly NOT prevention, NOT
  tamper-proof, NOT effective against root.
- CI: build + vet + test, matrix `ubuntu/windows/macos-latest` (portability stays honest
  even though only Linux ships).
*Acceptance:* CI green on all three platforms; README contains no claim contradicted by
`intake.md` § Threat model.

**T-002 · Go GC-pause spike (D19)** — `est 3h` — **blocks T-006**
The one decision hanging on a measurement. Synthetic harness: a Go process answering simulated
fanotify permission events under allocation pressure and load. Measure p50/p99/max response
latency and GC pause distribution.
*Acceptance:* a recorded number and a written verdict — Go stays for the responder, or the
responder is carved out (cgo/Rust helper). **Either outcome is a pass**; an unmeasured
assumption is the failure.

**T-003 · Event schema + Decision contract** — `est 4h`
Protobuf. The hardest things to change later. Must encode, from day one:
- `Decision` carries **confidence, not certainty** (D4) and a **closed, typed action set**
  (D14: Block/Alert/Quarantine-local/Encrypt-local — never an open action framework, or a
  compromised control plane can express "upload to URL")
- Classification output = **type + confidence + count only** (D10) — no content, no
  exact-match hashes of low-entropy PII
- **Stable pseudonymous user ID** (D23), purpose tag (D20)
- Enforcers receive *only* the Decision — never the classifier, regex or model that produced it
*Acceptance:* generated Go types; a compile-time test that the enforcer interface cannot see
classifier internals; peer review against `review-r1.md` §A4, §A6.

**T-004 · Peer-UEBA paper design — the hard fitness test (A1, D23)** — `est 3h` — *depends T-003*
**No code.** Design peer-baseline UEBA as an Analytics-stage module against the T-003 schema.
It is stateful, aggregating and cross-entity — it breaks every assumption a DLP-shaped pipeline
makes, unlike an S3 connector which is isomorphic to what exists and proves nothing.
*Acceptance:* a written design plus an explicit verdict — *does this require core changes?*
If yes, **revise T-003 now**. This is the cheapest possible test of the project's central claim,
and finding "yes" here is a success, not a setback.

### M1 — Walking skeleton (one event, end to end)

**T-005 · fanotify observe spike** — `est 3h`
Empirical, following M1 in `scouting-r1.md`. Establish: which events we get unprivileged
(`FAN_REPORT_FID`), whether file content is readable for classification or whether
`CAP_DAC_READ_SEARCH` is required, and what the deployed agent will need.
*Acceptance:* documented capability matrix; a clear statement of what the shipped agent
requires. **Sandbox limits inform the dev loop only — they never shape the product** (see
`scouting-r1.md` M1 scope warning).

**T-006 · Agent skeleton, privilege-split from commit one (D13)** — `est 5h` — *depends T-002, T-005*
Two processes, not one, because process boundaries are expensive to retrofit:
- privileged: fanotify hooks only. **Never parses attacker-controlled bytes.**
- unprivileged worker: all content parsing, returns structured verdicts over IPC.
Seccomp/cgroup hardening deferred to M2 — the *boundary* is what must exist now.
*Acceptance:* privileged process demonstrably never opens file content; IPC carries verdicts
only.

**T-007 · Pattern classifier (D5, D10)** — `est 4h` — *depends T-006*
Runs in the unprivileged worker. Regex + checksum validators — **Luhn for cards, CPF check
digits for Brazil**. Format+checksum detection only; emits type + confidence + count.
No spaCy/NER (not endpoint-viable), no exact-match hashing of low-entropy PII.
*Acceptance:* detects seeded CPF/card/SSN test fixtures; **transmits no content and no
reversible hash** — asserted by test, not by inspection.

**T-008 · Local policy evaluation → Decision** — `est 4h` — *depends T-003, T-007*
Local policy file (no control plane in Phase 1 — a fleet of one doesn't need distribution).
OPA/Rego evaluated natively in Go. Produces a `Decision` with confidence.
*Acceptance:* a policy over classifier output yields a well-formed Decision; identical input →
identical Decision.

**T-009 · Audit ledger — hash chain + forward integrity (D12)** — `est 5h` — *depends T-003*
Postgres as the system of record. NATS JetStream is a **bus only**, never the audit store
(bounded retention ≠ system of record). Key-evolving forward integrity so an attacker who
compromises the agent cannot rewrite entries from *before* compromise.
*Acceptance:* a tampering test detects modification; docs say **"tamper-evident with
forward-integrity between anchors"** and never "tamper-proof". External anchoring is designed
but may land in M2.

**T-010 · CLI query over the audit store** — `est 2h` — *depends T-009*
Replaces the React investigation UI, which is cut from Phase 1. Reconstruct an incident
timeline via CLI/SQL.
*Acceptance:* a seeded incident renders as an ordered timeline.

### M2 — The properties that make it real

**T-011 · Fail-open watchdog, exercised for real (D17, D18)** — `est 4h` — *depends T-006*
The riskiest contract in the system, and USB enforcement does **not** test it (attach-time
allow/deny has no blocked process, no timeout, no race). Build the watchdog now even though
Phase 1 verdicts are always-allow: self-PID bypass, response timeout → auto-`FAN_ALLOW`, safe
teardown. Every timeout-allow emits a **high-severity audit event** — never silence. Scan
budgets capped (max bytes, backtracking budget, per-process circuit breaker).
*Acceptance:* injected-delay test proves auto-allow fires and is loudly audited; a zip-bomb
fixture hits the budget ceiling rather than hanging.

**T-012 · Parser sandbox hardening (D13)** — `est 3h` — *depends T-006*
seccomp-bpf, no network, cgroup memory/CPU limits, decompression-bomb limits (ratio, expanded
size, nesting depth) on the worker from T-006. Precedent for why this is mandatory: ClamAV
CVE-2025-20260, a PDF-parser heap overflow → RCE.
*Acceptance:* worker cannot open a socket; bomb fixtures are rejected before parsing.

**T-013 · Privacy-law product features (D20, L1)** — `est 5h` — *depends T-003, T-009*
Architecture, not later additions: enforced retention with automatic purge, purpose tagging,
**exclusion lists as a first-class policy primitive** (personal folders, break time),
pseudonymisation by default, and an audit trail of **who viewed an investigation** — not only
who acted.
*Acceptance:* retention purge demonstrably runs; an excluded path produces no event; viewing an
investigation writes an audit row.

**T-014 · CI architectural fitness test (A1)** — `est 3h` — *depends T-004*
Adding a Connector must produce zero diffs in core packages. **Known-weak on its own** — an S3
connector is isomorphic to what exists, and the test is gamable via `map[string]any` typing or
reaching around the bus into shared tables. Pair it with the T-004 paper verdict; do not treat
green CI alone as validation of the 10-year claim.
*Acceptance:* test passes for a new connector; the T-004 verdict is recorded next to it.

### M3 — Dogfood

**T-015 · Deploy to owner's fleet, measure operability** — `est 4h` — *depends M1, M2*
Install, upgrade, idle overhead, false-positive rate on real files, fail-open-on-crash
behaviour. Operability is part of done (`intake.md` § Why now).
*Acceptance:* runs a week on the owner's machines without degrading them; FP rate recorded.
**Expected limitation, not a failure:** the owner has root, so this validates
pipeline/classifier/operability — it **cannot** validate the product as a control (D16).

## Explicitly NOT in Phase 1

React investigation UI · distributed/versioned policy control plane · full OTel span coverage ·
the Hub (and its ed25519 signing, D15 — designed, not built) · Windows/macOS agents ·
enforcement verdicts other than allow · embeddings or ML classification · any second connector
beyond the fitness test.

## Verification (end to end)

1. `podman compose up` brings up Postgres + control plane.
2. Agent starts privilege-split; `ps`/`/proc` confirms the privileged process holds no file
   content and the worker holds no `CAP_SYS_ADMIN`.
3. Write a file containing a seeded test CPF to a watched path.
4. Event → classification (type+confidence+count only) → policy → Decision → audit row.
5. `openshieldctl timeline --host <h>` renders the incident.
6. Tamper test: modify an audit row directly in Postgres; verification detects it.
7. Privacy test: packet capture / DB inspection confirms **no file content and no reversible
   low-entropy hash** ever leaves the endpoint.
8. Fail-open test: inject classifier delay; auto-allow fires and is audited high-severity.
9. `go test ./...` green on the three-platform CI matrix.

## Execution notes

- Tickets go to `tickets.jsonl` via
  `python3 ~/workspace/homelab/bootstrap/scripts/tickets.py add --case ~/workspace/openshield ...`
- `est_agent_h` is 24/7 agent wall-clock, **not** human time. The real schedule driver is owner
  decision latency (`intake.md`).
- Backend stack (Go + NATS + Postgres) likely needs a dev pod: `dev_env up openshield`.
- TDD for core pipeline logic. The privacy and tamper-evidence properties are asserted **by
  test**, never by inspection — they are the claims most likely to rot silently.
