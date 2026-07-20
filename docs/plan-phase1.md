# OpenShield — Phase 1 Plan

**29 tickets · ~122 agent-hours · Phase 1 is observe-and-audit only.**

This file is the **roadmap**: what gets built, in what order, and why that order. It is the
single source of truth for scope and sequencing — the machine-readable ticket queue that used
to live alongside it was deleted after the two drifted apart within a day of each other.

Three documents, three jobs, no overlap:

| Job | Home |
|---|---|
| **Why** — decisions and rationale | [`decisions.md`](decisions.md) + the append-only research reports |
| **What / when** — this file | roadmap, sequencing, dependencies |
| **How / now** — active work | `openspec/changes/` |

Not every ticket becomes an OpenSpec change. **Spikes and measurements** (T-002, T-005) are
throwaway code answering a question. **Infrastructure** (T-025, T-026, T-028) is mechanical.
**Capability work** (T-003, T-022, T-007, T-009) has real design space and long-lived
contracts — those get a change, and the change references its ticket ID.

`est` is 24/7 agent wall-clock, not human time. The real schedule driver is owner decision
latency.

## Context

OpenShield is a greenfield open-source Data Security Platform. The bet: a fixed pipeline
(Event → Classification → Policy → Decision → Enforcement → Audit) absorbs a decade of
capabilities by only adding plugins. DLP is capability #1, not the product.

Two rounds of work preceded this plan, both in `docs/`:
[`research-scouting-r1.md`](research-scouting-r1.md) (D1-D9) and
[`research-review-r1.md`](research-review-r1.md) (D10-D23, four adversarial reviewers, verdict:
*the pipeline architecture largely survives; the brief's stated principles do not*). A third
round reviewed this plan itself and found it could have been completed 100% while failing to
deliver its headline claims — D16 tamper-detection and D12 external anchoring had no
implementing ticket at all.

**Why analysis stopped here.** The research itself found that prior OSS DLP died of ambition
outrunning delivery (MyDLP, OpenDLP, Apache Metron). Everything still open is empirical
(T-002's measurement) or an owner call. The remaining risk is retired by building.

## Sequencing principle

Ordered by **risk retired per hour**, not dependency convenience:
1. Decisions that are hard to reverse (schema, contracts, process boundaries) come first.
2. Measurements that could invalidate a decision come before code depending on it.
3. The paper test of the 10-year claim (T-004) happens before the code that assumes it.

## Tickets

### M0 — Foundations (retire the reversible-decision risk)

#### T-001 · Repo skeleton + governance docs · **done**
`~1h` · depends: —

MOSTLY DONE 2026-07-20: repo created+pushed; LICENSE(Apache-2.0), README (honest claims), SECURITY.md (solo-meetable SLA), CONTRIBUTING.md (AI-authorship disclosure D22/L3), ETHICS.md (L5), .gitignore, docs/ consolidation, docs/decisions.md canonical register all landed. REMAINING: Go module layout (cmd/, internal/{core,agent,connectors,enforcers}) + 3-platform CI matrix + the CI denylist grep on overclaiming words (that check is T-029).

#### T-002 · Go GC-pause spike for fanotify responder (D19) · **done**
`~3h` · depends: —

Recorded p50/p99/max response latency + GC pause distribution under allocation pressure; written verdict: Go stays for the responder OR responder is carved out. Either outcome passes; an unmeasured assumption is the failure.

#### T-003 · Event schema + Decision contract (protobuf)
`~4h` · depends: —

Protobuf. Decision carries confidence not certainty (D4) + CLOSED typed action set (D14); classification output = type+confidence+count only (D10); stable pseudonymous user ID (D23) + purpose tag (D20); compile-time test that enforcers cannot see classifier internals. ESCAPE HATCH (review finding): T-005 has not yet characterised what fanotify actually delivers (file handles vs paths). If T-005 contradicts the schema, REVISE T-003 immediately - before T-007/T-008/T-009 build on it. Same 'revise now if wrong' licence as T-004.

#### T-004 · Peer-UEBA paper design - the hard fitness test (A1/D23)
`~3h` · depends: T-003

NO CODE. Written design of peer-baseline UEBA as an Analytics module against the T-003 schema, plus explicit verdict: does it require core changes? If yes, revise T-003 now. Finding yes is a success.


### M1 — Walking skeleton (one event, end to end)

#### T-005 · fanotify observe spike
`~3h` · depends: —

Documented capability matrix (which events unprivileged via FAN_REPORT_FID; is content readable or is CAP_DAC_READ_SEARCH required); clear statement of what the SHIPPED agent needs. Sandbox limits inform the dev loop only, never the product.

#### T-006 · Agent skeleton, privilege-split from commit one (D13)
`~8h` · depends: T-002, T-005

Two processes. TESTABLE: privileged binary is a separate Go module with an import ALLOWLIST excluding encoding/*, compress/*, archive/* and any parser pkg - CI fails build via 'go list -deps' diff if a disallowed import appears; plus a runtime strace/seccomp-audit test asserting no read() beyond dirent/metadata syscalls. Unprivileged worker does all parsing, returns verdicts over IPC.

#### T-007 · Pattern classifier: regex + checksum validators (D5/D10)
`~5h` · depends: T-003, T-006

Runs in unprivileged worker. Luhn + CPF check digits. TESTABLE: reflect emitted Classification message - fields must be EXACTLY enum-type + float-confidence + int-count; AND grep serialized wire bytes across seeded-PII fixtures for any substring of seed values (must find none). No content, no reversible hash.

#### T-008 · Local policy evaluation to Decision
`~4h` · depends: T-003, T-007

Local policy file (no control plane in Phase 1); OPA/Rego native in Go; policy over classifier output yields well-formed Decision; identical input yields identical Decision.

#### T-009 · Audit ledger: Postgres hash chain + forward integrity (D12)
`~8h` · depends: T-003, T-026

Postgres = system of record; JetStream = bus only. Key-evolving forward integrity: post-compromise attacker cannot rewrite pre-compromise entries. Tampering test detects direct-DB modification. Docs say tamper-EVIDENT, never tamper-proof. External anchoring is T-017, NOT hand-waved here.

#### T-010 · CLI query over audit store (replaces React UI)
`~2h` · depends: T-009

Seeded incident renders as an ordered timeline via CLI/SQL.

#### T-016 · Trivial wiring proof - one event end to end, stubs only
`~2h` · depends: T-005, T-022

Hardcoded-verdict classifier stub + flat-file audit sink; ONE real fanotify event traverses the full path. Proves the wiring before ~13h of real classifier+ledger work is committed. Deliberately throwaway.

#### T-022 · Event bus / pipeline dispatcher - the backbone
`~6h` · depends: T-003

The stage-to-stage dispatcher the whole architecture rests on: Event->Classification->Policy->Decision->Enforcement->Audit, with stages registered as plugins rather than wired by hand. NATS JetStream integration for the transport. THIS WAS MISSING ENTIRELY from the first two ticket passes despite the brief calling the Event Bus 'the backbone of the platform'. Acceptance: a stage can be added/removed without editing another stage; replay from the bus reproduces a decision.

#### T-023 · Control plane service
`~6h` · depends: T-003, T-022

The server side referenced by T-017 (mTLS), T-018 (heartbeat) and the verification steps but never built: receives agent telemetry, serves the audit store, exposes the API the CLI queries. NOT policy distribution (cut from Phase 1 - local policy file). Acceptance: agent connects, telemetry lands in Postgres, CLI reads it back.

#### T-024 · Offline store-and-forward queue on the agent
`~5h` · depends: T-022

'Offline-capable' is a stated core principle and nothing implemented it. When the control plane is unreachable the agent must durably queue events on disk and forward on reconnect - NEVER silently drop. Bounded with an explicit overflow policy (and overflow itself is an audit event). Acceptance: kill the control plane, generate events, restart it, all events arrive in order; fill the queue to its ceiling and assert the documented overflow behaviour.

#### T-026 · DB schema + migrations
`~4h` · depends: T-003

Versioned, forward-only migrations for the audit ledger and telemetry tables. Must accommodate D12's hash-chain columns and D13/D20's retention+purpose+pseudonymisation fields from the start - retrofitting columns into a hash-chained ledger is expensive. Acceptance: migrate up from empty on a clean DB; schema matches the T-003 protobuf shape.


### M2 — The properties that make it real

#### T-011 · Fail-open watchdog, exercised for real (D17/D18)
`~4h` · depends: T-006

Self-PID bypass, response timeout to auto-FAN_ALLOW, safe teardown. Injected-delay test proves auto-allow fires AND is audited high-severity. Zip-bomb fixture hits budget ceiling rather than hanging. Scan budgets capped.

#### T-012 · Parser sandbox hardening (D13)
`~5h` · depends: T-006

seccomp-bpf, no network, cgroup mem/CPU limits, decompression-bomb limits (ratio/size/nesting). Worker cannot open a socket; bomb fixtures rejected before parsing. Precedent: ClamAV CVE-2025-20260.

#### T-013 · Privacy-law product features (D20/L1)
`~8h` · depends: T-003, T-009

Retention purge demonstrably runs; excluded path produces no event; viewing an investigation writes an audit row. PLUS the three L1 items previously dropped: employee-visible notice mechanism; four-eyes gate before any HR-visible outcome; DPIA template shipped in docs/. Purpose tagging + pseudonymisation by default. Exclusion lists are a first-class policy primitive.

#### T-014 · CI architectural fitness test (A1)
`~3h` · depends: T-004, T-008, T-009

Adding a Connector produces zero diffs in core packages. KNOWN-WEAK alone (S3 is isomorphic; gamable via map[string]any). T-004 paper verdict recorded alongside; green CI is not by itself validation of the 10-year claim.

#### T-017 · Agent identity + enrollment (A6)
`~4h` · depends: T-006, T-023

Per-agent revocable identity; mTLS to the control plane; single-use short-TTL enrollment token or TOFU-with-admin-approval. NEVER a shared fleet secret (one compromised agent must not equal fleet compromise). Telemetry individually signed w/ sequence numbers - it is evidentiary, same integrity bar as the audit log.

#### T-018 · Tamper-detection: heartbeat / dead-man's-switch (D16)
`~4h` · depends: T-009, T-023

Agent heartbeat to control plane; 'agent last seen' per host; alert when telemetry silence exceeds threshold; audit event emitted when the systemd unit stops/is masked. This IMPLEMENTS the honest claim replacing 'tamper-proof' - without it the README claim is unbacked.

#### T-019 · Audit log external anchoring (D12/B3)
`~4h` · depends: T-009

Merkle root periodically anchored to a trust domain outside the agent: second host, WORM/object-lock storage, or a public transparency service when online. Documents the honest boundary: tamper-evident WITH forward-integrity BETWEEN anchors; full tamper-proofing needs a witness the deployer does not control.

#### T-020 · USB event + trivial USB enforcer (D1)
`~4h` · depends: T-003, T-008

USBInserted event producer + a real (non-stub) USB enforcer via authorized_default, proving the Enforcer interface end-to-end with an actual enforcement point. Restores D1's explicit 'ship one trivial USB enforcer to prove the interface', silently dropped in the first ticket pass. Note A8: this does NOT test the fail-open/blocking contract - that is T-011.

#### T-021 · Open-core separability boundary test (D21)
`~2h` · depends: T-008

CI test asserting core packages do not import Hub / compliance-pack / multi-tenant-control-plane packages, so an open-core split stays cheap. Retrofitting this boundary later is expensive; enforcing it costs one test now.

#### T-025 · Podman compose dev stack
`~3h` · depends: T-001

Postgres + NATS + control plane up from a clean checkout with one command. The plan's own verification section opens with 'podman compose up' and no ticket built it. Podman rootless, not Docker. Acceptance: clean clone to running stack, no manual steps.

#### T-027 · Packaging: systemd unit + install/upgrade path
`~5h` · depends: T-006

T-015 asserts 'install and upgrade exercised' and nothing built either. systemd unit for the privileged process and the unprivileged worker, correct capability grants (not blanket root where avoidable), Restart=always, clean upgrade that does not lose the offline queue. Acceptance: install, upgrade across versions, and uninstall on a clean Linux VM/container without manual repair.

#### T-028 · Structured logging + agent error handling
`~3h` · depends: T-006

OTel is cut from Phase 1 but the agent still needs to be debuggable: structured logs, error taxonomy, and defined behaviour when a stage fails (fail-open per D17 where a verdict is involved, loud audit event always). Acceptance: every stage failure path emits a log with correlation id; no silent swallow.

#### T-029 · CI doc-consistency check
`~3h` · depends: T-001

Mechanises the drift that hit brief.md twice. IMPORTANT - a naive denylist grep DOES NOT WORK (proven 2026-07-20: it false-positived on 4 legitimate uses, because this project's discipline consists of discussing the forbidden words). Design: (1) scan CLAIM SURFACES only - README.md and future user-facing/marketing copy - not all docs; (2) support an inline '<!-- allow: <term> -->' escape for deliberate discussion; (3) append-only research reports under docs/research-* are excluded entirely; (4) separately assert that living docs reference D-numbers rather than restating them (flag paragraphs >3 lines adjacent to a D-ref). Acceptance: check passes on the current tree, and fails on a test fixture asserting 'OpenShield provides tamper-proof audit logs' in README.


### M3 — Dogfood

#### T-015 · Dogfood on owner fleet, measure operability
`~6h` · depends: T-007, T-008, T-010, T-011, T-012, T-013, T-027

QUANTIFIED, not vibes: explicit idle CPU%/RSS ceilings defined and met; before/after file-op latency benchmark recorded; install+upgrade exercised; FP rate on real files recorded; fail-open-on-crash verified. NOTE units: ~6 agent-h of build/measure work wrapped around an unavoidable ~1-week calendar soak. Validates pipeline+classifier+operability, NOT the product as a control (D16 - owner has root).

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

- **This file is the ticket queue.** The machine-readable `tickets.jsonl` was deleted after it
  and this document drifted apart within a day. One roadmap, one source of truth.
- Work that warrants a spec becomes an OpenSpec change under `openspec/changes/`, referencing
  its ticket ID. Spikes and mechanical infrastructure do not.
- `est_agent_h` is 24/7 agent wall-clock, **not** human time. The real schedule driver is owner
  decision latency ([`brief.md`](brief.md)).
- Backend stack (Go + NATS + Postgres) likely needs a dev pod: `dev_env up openshield`.
- TDD for core pipeline logic. The privacy and tamper-evidence properties are asserted **by
  test**, never by inspection — they are the claims most likely to rot silently.
