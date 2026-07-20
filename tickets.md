# Tickets


## TODO (29)

- **T-001** Repo skeleton + governance docs  _(~3.0h)_
    - ✓ CI green on ubuntu/windows/macos-latest. LICENSE(Apache-2.0); SECURITY.md w/ solo-meetable SLA; CONTRIBUTING.md disclosing AI authorship (D22/L3); README honest claims. TESTABLE FLOOR: CI denylist grep fails the build on 'tamper-proof'|'prevents exfiltration'|'guarantee'|'unbreakable' in docs, plus manual sign-off vs intake.md threat-model table. Also: Apache-2.0 s7 deployer-liability note in README (L2); ETHICS.md stating conscious permissive dual-use posture (L5). Repo+push DONE 2026-07-20.
- **T-002** Go GC-pause spike for fanotify responder (D19)  _(~3.0h)_
    - ✓ Recorded p50/p99/max response latency + GC pause distribution under allocation pressure; written verdict: Go stays for the responder OR responder is carved out. Either outcome passes; an unmeasured assumption is the failure.
- **T-003** Event schema + Decision contract (protobuf)  _(~4.0h)_
    - ✓ Protobuf. Decision carries confidence not certainty (D4) + CLOSED typed action set (D14); classification output = type+confidence+count only (D10); stable pseudonymous user ID (D23) + purpose tag (D20); compile-time test that enforcers cannot see classifier internals. ESCAPE HATCH (review finding): T-005 has not yet characterised what fanotify actually delivers (file handles vs paths). If T-005 contradicts the schema, REVISE T-003 immediately - before T-007/T-008/T-009 build on it. Same 'revise now if wrong' licence as T-004.
- **T-004** Peer-UEBA paper design - the hard fitness test (A1/D23)  _(~3.0h · deps: T-003)_
    - ✓ NO CODE. Written design of peer-baseline UEBA as an Analytics module against the T-003 schema, plus explicit verdict: does it require core changes? If yes, revise T-003 now. Finding yes is a success.
- **T-005** fanotify observe spike  _(~3.0h)_
    - ✓ Documented capability matrix (which events unprivileged via FAN_REPORT_FID; is content readable or is CAP_DAC_READ_SEARCH required); clear statement of what the SHIPPED agent needs. Sandbox limits inform the dev loop only, never the product.
- **T-006** Agent skeleton, privilege-split from commit one (D13)  _(~8.0h · deps: T-002, T-005)_
    - ✓ Two processes. TESTABLE: privileged binary is a separate Go module with an import ALLOWLIST excluding encoding/*, compress/*, archive/* and any parser pkg - CI fails build via 'go list -deps' diff if a disallowed import appears; plus a runtime strace/seccomp-audit test asserting no read() beyond dirent/metadata syscalls. Unprivileged worker does all parsing, returns verdicts over IPC.
- **T-007** Pattern classifier: regex + checksum validators (D5/D10)  _(~5.0h · deps: T-003, T-006)_
    - ✓ Runs in unprivileged worker. Luhn + CPF check digits. TESTABLE: reflect emitted Classification message - fields must be EXACTLY enum-type + float-confidence + int-count; AND grep serialized wire bytes across seeded-PII fixtures for any substring of seed values (must find none). No content, no reversible hash.
- **T-008** Local policy evaluation to Decision  _(~4.0h · deps: T-003, T-007)_
    - ✓ Local policy file (no control plane in Phase 1); OPA/Rego native in Go; policy over classifier output yields well-formed Decision; identical input yields identical Decision.
- **T-009** Audit ledger: Postgres hash chain + forward integrity (D12)  _(~8.0h · deps: T-003, T-026)_
    - ✓ Postgres = system of record; JetStream = bus only. Key-evolving forward integrity: post-compromise attacker cannot rewrite pre-compromise entries. Tampering test detects direct-DB modification. Docs say tamper-EVIDENT, never tamper-proof. External anchoring is T-017, NOT hand-waved here.
- **T-010** CLI query over audit store (replaces React UI)  _(~2.0h · deps: T-009)_
    - ✓ Seeded incident renders as an ordered timeline via CLI/SQL.
- **T-011** Fail-open watchdog, exercised for real (D17/D18)  _(~4.0h · deps: T-006)_
    - ✓ Self-PID bypass, response timeout to auto-FAN_ALLOW, safe teardown. Injected-delay test proves auto-allow fires AND is audited high-severity. Zip-bomb fixture hits budget ceiling rather than hanging. Scan budgets capped.
- **T-012** Parser sandbox hardening (D13)  _(~5.0h · deps: T-006)_
    - ✓ seccomp-bpf, no network, cgroup mem/CPU limits, decompression-bomb limits (ratio/size/nesting). Worker cannot open a socket; bomb fixtures rejected before parsing. Precedent: ClamAV CVE-2025-20260.
- **T-013** Privacy-law product features (D20/L1)  _(~8.0h · deps: T-003, T-009)_
    - ✓ Retention purge demonstrably runs; excluded path produces no event; viewing an investigation writes an audit row. PLUS the three L1 items previously dropped: employee-visible notice mechanism; four-eyes gate before any HR-visible outcome; DPIA template shipped in docs/. Purpose tagging + pseudonymisation by default. Exclusion lists are a first-class policy primitive.
- **T-014** CI architectural fitness test (A1)  _(~3.0h · deps: T-004, T-008, T-009)_
    - ✓ Adding a Connector produces zero diffs in core packages. KNOWN-WEAK alone (S3 is isomorphic; gamable via map[string]any). T-004 paper verdict recorded alongside; green CI is not by itself validation of the 10-year claim.
- **T-015** Dogfood on owner fleet, measure operability  _(~6.0h · deps: T-007, T-008, T-010, T-011, T-012, T-013, T-027)_
    - ✓ QUANTIFIED, not vibes: explicit idle CPU%/RSS ceilings defined and met; before/after file-op latency benchmark recorded; install+upgrade exercised; FP rate on real files recorded; fail-open-on-crash verified. NOTE units: ~6 agent-h of build/measure work wrapped around an unavoidable ~1-week calendar soak. Validates pipeline+classifier+operability, NOT the product as a control (D16 - owner has root).
- **T-016** Trivial wiring proof - one event end to end, stubs only  _(~2.0h · deps: T-005, T-022)_
    - ✓ Hardcoded-verdict classifier stub + flat-file audit sink; ONE real fanotify event traverses the full path. Proves the wiring before ~13h of real classifier+ledger work is committed. Deliberately throwaway.
- **T-017** Agent identity + enrollment (A6)  _(~4.0h · deps: T-006, T-023)_
    - ✓ Per-agent revocable identity; mTLS to the control plane; single-use short-TTL enrollment token or TOFU-with-admin-approval. NEVER a shared fleet secret (one compromised agent must not equal fleet compromise). Telemetry individually signed w/ sequence numbers - it is evidentiary, same integrity bar as the audit log.
- **T-018** Tamper-detection: heartbeat / dead-man's-switch (D16)  _(~4.0h · deps: T-009, T-023)_
    - ✓ Agent heartbeat to control plane; 'agent last seen' per host; alert when telemetry silence exceeds threshold; audit event emitted when the systemd unit stops/is masked. This IMPLEMENTS the honest claim replacing 'tamper-proof' - without it the README claim is unbacked.
- **T-019** Audit log external anchoring (D12/B3)  _(~4.0h · deps: T-009)_
    - ✓ Merkle root periodically anchored to a trust domain outside the agent: second host, WORM/object-lock storage, or a public transparency service when online. Documents the honest boundary: tamper-evident WITH forward-integrity BETWEEN anchors; full tamper-proofing needs a witness the deployer does not control.
- **T-020** USB event + trivial USB enforcer (D1)  _(~4.0h · deps: T-003, T-008)_
    - ✓ USBInserted event producer + a real (non-stub) USB enforcer via authorized_default, proving the Enforcer interface end-to-end with an actual enforcement point. Restores D1's explicit 'ship one trivial USB enforcer to prove the interface', silently dropped in the first ticket pass. Note A8: this does NOT test the fail-open/blocking contract - that is T-011.
- **T-021** Open-core separability boundary test (D21)  _(~2.0h · deps: T-008)_
    - ✓ CI test asserting core packages do not import Hub / compliance-pack / multi-tenant-control-plane packages, so an open-core split stays cheap. Retrofitting this boundary later is expensive; enforcing it costs one test now.
- **T-022** Event bus / pipeline dispatcher - the backbone  _(~6.0h · deps: T-003)_
    - ✓ The stage-to-stage dispatcher the whole architecture rests on: Event->Classification->Policy->Decision->Enforcement->Audit, with stages registered as plugins rather than wired by hand. NATS JetStream integration for the transport. THIS WAS MISSING ENTIRELY from the first two ticket passes despite the brief calling the Event Bus 'the backbone of the platform'. Acceptance: a stage can be added/removed without editing another stage; replay from the bus reproduces a decision.
- **T-023** Control plane service  _(~6.0h · deps: T-003, T-022)_
    - ✓ The server side referenced by T-017 (mTLS), T-018 (heartbeat) and the verification steps but never built: receives agent telemetry, serves the audit store, exposes the API the CLI queries. NOT policy distribution (cut from Phase 1 - local policy file). Acceptance: agent connects, telemetry lands in Postgres, CLI reads it back.
- **T-024** Offline store-and-forward queue on the agent  _(~5.0h · deps: T-022)_
    - ✓ 'Offline-capable' is a stated core principle and nothing implemented it. When the control plane is unreachable the agent must durably queue events on disk and forward on reconnect - NEVER silently drop. Bounded with an explicit overflow policy (and overflow itself is an audit event). Acceptance: kill the control plane, generate events, restart it, all events arrive in order; fill the queue to its ceiling and assert the documented overflow behaviour.
- **T-025** Podman compose dev stack  _(~3.0h · deps: T-001)_
    - ✓ Postgres + NATS + control plane up from a clean checkout with one command. The plan's own verification section opens with 'podman compose up' and no ticket built it. Podman rootless, not Docker. Acceptance: clean clone to running stack, no manual steps.
- **T-026** DB schema + migrations  _(~4.0h · deps: T-003)_
    - ✓ Versioned, forward-only migrations for the audit ledger and telemetry tables. Must accommodate D12's hash-chain columns and D13/D20's retention+purpose+pseudonymisation fields from the start - retrofitting columns into a hash-chained ledger is expensive. Acceptance: migrate up from empty on a clean DB; schema matches the T-003 protobuf shape.
- **T-027** Packaging: systemd unit + install/upgrade path  _(~5.0h · deps: T-006)_
    - ✓ T-015 asserts 'install and upgrade exercised' and nothing built either. systemd unit for the privileged process and the unprivileged worker, correct capability grants (not blanket root where avoidable), Restart=always, clean upgrade that does not lose the offline queue. Acceptance: install, upgrade across versions, and uninstall on a clean Linux VM/container without manual repair.
- **T-028** Structured logging + agent error handling  _(~3.0h · deps: T-006)_
    - ✓ OTel is cut from Phase 1 but the agent still needs to be debuggable: structured logs, error taxonomy, and defined behaviour when a stage fails (fail-open per D17 where a verdict is involved, loud audit event always). Acceptance: every stage failure path emits a log with correlation id; no silent swallow.
- **T-029** CI doc-consistency check  _(~2.0h · deps: T-001)_
    - ✓ Mechanises the drift that bit intake.md twice: CI greps the LIVING docs (intake.md, case.md, README) for superseded terms - 'Rust' outside an allowlisted historical context, unqualified 'tamper-proof', 'CEL', 'policy IR' - and fails the build. Reports are append-only historical records and are excluded. The only mechanism here that does not depend on someone remembering.

## DOING (0)


## BLOCKED (0)


## DONE (0)


---
_agent-hours: 0.0 done · 123.0 remaining (29 tickets)_
