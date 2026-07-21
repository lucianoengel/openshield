# OpenShield architecture roadmap — the hard pieces

> Companion to [`decisions.md`](decisions.md) (D1–D84). This plans the capabilities an
> adversarial audit found MISSING or ARCHITECTURALLY BLOCKED — HIPS, non-HTTP/transparent
> NIPS, real Zero-Trust identity, inline prevention, detection depth, SIEM depth,
> cross-platform. It is a design document, not a commitment; the sequencing and the open
> decisions at the end are for the owner to steer.

## The lens: does it fit the frozen pipeline?

The bet is a fixed pipeline — **Event → Classify → Policy → Decision → Enforce → Audit** —
that absorbs capabilities as plugins, proven data-plane-agnostic three times (endpoint
files D48, peer-UEBA D53, network gateway D69). Every missing piece is classified by how it
meets that pipeline:

- **P — Producer plugin.** A new Event source (a connector). Additive; the D69 seam holds.
- **C — Classify plugin.** A new detector/analyzer in the sandboxed worker. Additive.
- **X — Context input.** A new typed Policy input via the `ResolveContext`/`State.Context`
  seam (D28/D53). Additive — this is the seam identity and risk flow through.
- **A — Action expansion.** A new verb in the **closed** `Action` set (D14). NOT additive
  in spirit — the closed set is a security feature (a compromised control plane cannot
  express "upload to URL"). Each new action is a deliberate, typed, single-purpose
  expansion, decided one at a time, never a generic "run command."
- **D — New data-plane shape.** A new connector topology (transparent/inline vs
  forward-proxy). The pipeline is unchanged; the connector is new.
- **E — External gating.** Not a design problem (certs, entitlements, ecosystem).

The recurring discipline: **the core stays frozen; capability lands in producers, classify
plugins, typed context, and — rarely and deliberately — one new action at a time.**

---

## The three architectural tensions to decide first

Everything below hangs on three decisions. They are called out here because they are
value/scope choices, not engineering ones.

### T1 — Does the closed action set (D14) expand, and how far?
The closed set (`ALLOW/ALERT/BLOCK/QUARANTINE_LOCAL/ENCRYPT_LOCAL/REDIRECT`) deliberately
**cannot express process control**. HIPS (deny-exec / kill), real inline file block, and
ZT deny-flow all want new verbs. The safe path is **one typed action at a time**
(`DENY_EXEC`, not "run command"; `KILL_PROCESS` as a distinct, audited verb), each with its
own enforcer and its own guard, so the surface a compromised control plane gains is exactly
one bounded capability, reviewed on its merits. The alternative — refusing all new actions —
caps the product at detect-and-contain forever. **Recommendation: expand, deliberately, one
verb per capability, never a parameterised/open framework (the D14 red line stays).**

### T2 — Does risk flow back to enforcement (closing the D54 dead-end)?
Zero-Trust continuous verification needs a control loop: risk must be able to gate a live
flow. Today peer-UEBA risk is a one-way, observe-only, server-side dead end (D54), because
"the server coordinates, it does not control" (D14). The reconciliation: **the server
computes risk and PUBLISHES it; the ENFORCEMENT decision stays local** — the endpoint/gateway
reads risk as a typed Policy input (the D28 context seam) and decides. The server informs;
it never actuates. That preserves D14's control-plane-can't-actuate property while enabling
risk-aware Zero Trust. **Recommendation: close the loop through the policy context (X), not
through server-issued commands.**

### T3 — One product or a platform? (DLP → XDR scope)
HIPS + non-HTTP NIPS + ZT is, honestly, an **XDR/NDR** ambition, not "DLP with plugins." The
pipeline can host it, but each is a subsystem-sized build with its own detection content.
**Recommendation: stay DLP-centric and deep before going XDR-broad** — a credible DLP (real
inline prevention, document parsing, secrets, cross-platform) is more valuable than a shallow
everything. Treat HIPS/NDR as explicit, separately-scoped bets, not the default trajectory.

---

## Phased plan

Ordered by leverage-per-architectural-risk. Each phase reuses proven seams where possible.

### Phase A — Identity & Zero-Trust foundation  (X + P + one A)
The highest-leverage architectural addition, and it mostly reuses seams.
- **A1. Identity producer at the proxy.** Authenticate the network subject: client cert
  (reuse the provisioning CA, D60) or an OIDC/bearer assertion, verified at the gateway
  BEFORE the pipeline. Replace the `sha256(src-IP)` pseudonym (D77/D84) with a verified,
  still-pseudonymised subject. **[P, and an auth layer — the real work.]**
- **A2. Identity + device posture as typed Policy context.** Feed `{identity, role,
  device_posture}` into Policy via the `State.Context` seam (D28) and the `ResolveContext`
  hook (D53) — the SAME mechanism peer-UEBA risk uses. Policy rules become identity-aware
  (`allow finance-group → payroll-api`). **[X — additive, the seam exists.]**
- **A3. Close the risk loop (T2).** Publish peer-UEBA/behavioral risk; the gateway/endpoint
  reads it as context and can `REDIRECT`/step-up. No new action needed for coaching;
  step-up-auth is a possible new verb. **[X, maybe one A.]**
- Endpoint parity: the agent already HAS an enrolled identity (D44) — extend the same
  context to endpoint policy so a decision can be user/device-aware there too.

**Why first:** unblocks the sharpest overclaim (ZT), reuses D28/D53/D60, and the identity
context it establishes is a prerequisite for meaningful HIPS and NDR policy.

### Phase B — Inline prevention, for real  (enforcement-timing, one A)
Closes D49 (all enforcement is post-decision today).
- **B1. Solve the classify-in-the-permission-window problem.** Two-tier: a fast synchronous
  pre-filter (size/type/cheap-signature) answers the fanotify PERMISSION event inside the
  budget; full classification stays async for audit/containment. Or stream/partial-classify.
- **B2. The privileged permission-mode agent.** Wire the already-built watchdog/responder
  (D18, currently dormant, D62) behind B1, under the fail-open contract.
- **B3. One new action: `BLOCK` becomes truly inline for files** (the enforcer exists; the
  timing is the gap). No new verb if BLOCK suffices; a distinct `DENY_OPEN` if the semantics
  differ. **[timing + at most one A.]**

**Why here:** it's the DLP product's biggest credibility gap (contain-after-the-fact →
prevent), and it needs the identity context (A) to decide *whose* action to block.

### Phase C — Network breadth & transparent inline  (P + D + C)
Makes the gateway a real NDR/NIPS data plane, not a configured forward proxy.
- **C1. Transparent/inline connector.** An nftables/TPROXY redirect or L2 bridge feeding the
  SAME pipeline — a new connector (D), not a core change; the D69 `NetworkSubject`/flow-table
  contract holds. Removes the "clients must be configured to proxy" limit.
- **C2. Non-HTTP producers.** DNS proxy/resolver (DNS-exfil + C2-over-DNS is the top NDR
  gap), SMTP, raw TCP/L4 metadata. New EventKinds + `NetworkSubject` fields; protocol parsers
  run in the sandbox (D72/D35). **[P + C.]**
- **C3. Response-body + multipart + decompression** at the gateway (audit found request-only,
  no multipart, no gzip). **[C — classify plugins.]**
- **C4. IDS-signature / anomaly classify plugin** (optional, Suricata-ruleset-style) as a
  network classifier. **[C.]**

### Phase D — Detection depth  (C, mostly)
Turns "4 regexes" into credible DLP detection.
- **D1. Document-structure parsing** (PDF/DOCX/XLSX) in the sandboxed worker — the RCE surface
  the split (D29/D35) was built for; now it earns its keep. **[C.]**
- **D2. Secrets/credentials, health data, IBAN/passport, keyword/dictionary detectors.** **[C.]**
- **D3. Admin-authorable detectors + policy.** A rule-authoring surface — which raises signed
  detector/policy DISTRIBUTION (the D14 "server doesn't push control" tension; signed,
  operator-approved rule bundles, not silent server push). **[C + a distribution decision.]**
- **D4. Optional ML/EDM** — deferred by D5/D11 on the endpoint; viable server-side or as an
  opt-in worker plugin. **[C.]**

### Phase E — HIPS  (P + a bounded A + C)  — an explicit XDR bet (T3)
Only if the platform bet is made.
- **E1. Exec-event producer** — fanotify `FAN_OPEN_EXEC_PERM` / eBPF-LSM / auditd. **[P.]**
- **E2. Behavioral classify domain** — allow/deny-list, LOLBin/process-lineage rules (a
  different classifier shape than content patterns). **[C.]**
- **E3. `DENY_EXEC` / `KILL_PROCESS`** — the deliberate action expansion (T1), each a distinct
  typed verb with its own enforcer and guard. **[A — the crux decision.]**
- FIM (file-integrity monitoring) and memory/injection detection are further, separate bets.

### Phase F — SIEM/analytics depth  (server-side, above the pipeline)
Builds on the operator read API (D82) and alert delivery (D83).
- **F1. Query/search API + filtering** over the fleet aggregate. **F2. Correlation/rules
  engine** (cross-host, cross-event) — peer-UEBA is the toy seed. **F3. Case/investigation
  workflow** (four-eyes D36, assignment, notice — T-013 remainder). **F4. Dashboards/UI** on
  top (the deferred UI, now with a real API + real fleet data behind it). **F5. Third-party
  log ingest** (syslog) if it becomes a SIEM, not just OpenShield's own telemetry.

### Cross-platform (Windows/macOS)  — parallel, external-gated (E)
Not a design problem: Windows needs an EV cert + attested minifilter; macOS needs an Apple
Endpoint Security entitlement. The pipeline/core is portable (all-Go, D8); the producers and
enforcers are per-OS. Sequence independently once the ecosystem gating is resolved; **most
enterprise data lives here, so this gates real-world DLP relevance more than any feature.**

---

## What stays frozen

The core does not change for any of the above: `core.Dispatcher`, `State`, `Stage`,
`Registry`, the `Enforcer`/`TargetedEnforcer` interfaces, `OnOutcome`, the ledger, the
boundary rule (D10/D29 — content stays in the classifying process; only type+count+metadata
cross). Capability lands in **producers, classify plugins, typed context, and one deliberate
action at a time.** If any phase forces a core change, that is the signal to stop and
re-examine — the same fitness test D26/D69 apply.

## Suggested order

**A (identity/ZT) → B (inline prevention) → D (detection depth) → C (network breadth) → F
(SIEM depth) → E (HIPS, only on the platform bet).** Cross-platform runs in parallel, gated
externally. A and B make the DLP product *credible*; C/D/F make it *broad and operable*; E is
the XDR fork.

---

# Audit-derived backlog (Round-30 — 2026-07-21)

> This section is the **pickup queue** produced by the Round-30 full enterprise audit
> (positioning OpenShield against DLP / HIPS / NTPS / NAC / SIEM / ZT / VPN). It is the
> single source for that audit's findings — every issue and missing feature is captured below
> as a discrete, actionable ticket. Items above (Phases A–F) describe the *shape* of the work;
> the items here are the *specific* work.
>
> **⚠️ Staleness warning.** This queue was written against the 2026-07-21 audit snapshot, and the
> repo moves fast — a builder is committing concurrently and **D103–D108 landed the same day**
> (alert search, correlation→incidents, case workflow, syslog ingest+listener), closing or
> narrowing several tickets below (marked _[verify — may be landed]_ / ✅ LANDED). **Before
> proposing ANY ticket, re-verify against `HEAD` that the gap still exists.**

## How the builder worker should consume this

- **Re-verify before proposing.** Open the cited files at `HEAD` and confirm the gap is still
  open — recent commits (D103–D108: search, correlation, case workflow, syslog) already closed or
  narrowed HON-2 / SIEM-2 / SIEM-3 / SIEM-4 and part of SIEM-1. Skip or re-scope a ticket whose
  gap is gone.
- **One canonical ID per unit of work.** Some work is cross-referenced under several IDs
  (HON-2≈SIEM-3≈DLP-4, HON-3≈DLP-1, SEC-10≈SIEM-5-persist, SEC-4⊂PLAT-2, NIPS-4∩DLP-8). Aliases
  are marked _alias — do not double-propose_; propose each unit once.
- **One OpenSpec change per ticket** (`openspec-propose` → implement → `openspec-archive`),
  per the standing workflow. Ticket IDs (`SEC-1`, `DLP-3`, …) are stable handles — reference
  them in the change name and commit.
- **Order is prescriptive where marked.** Do **Bucket S (security)** and **Bucket H
  (honesty)** before any new feature: they are cheap, they live in code that already works,
  and several undermine categories we already claim. Bucket P (platform) and the per-category
  features can then proceed in the revised order at the end of this section.
- **Evidence line numbers are as-of-audit (2026-07-21) and may drift** — treat `file:symbol`
  as the anchor and re-locate if a line moved. Open the file; do not trust the number.
- **Every ticket lists an acceptance test.** Honor the project's discipline: the test must
  exercise the **real substrate / a real adversary**, never a mock built from the code's own
  assumptions (the recurring "verifies against its own assumptions" failure — see
  `docs/decisions.md` and the phase-1 memory). For each negative security property, add the
  mutation that *would have let the bug through* and prove the test catches it.
- **The frozen core still governs.** If a ticket appears to force a change to `core.Dispatcher`
  / `State` / `Stage` / `Registry` / the `Enforcer` interfaces / `OnOutcome` / the ledger /
  the D10/D29 boundary, STOP and re-run the D26/D69 fitness reasoning — most of these fit as
  producers / classify plugins / typed context / one deliberate action, and where they do not
  (NAC, VPN) that is called out explicitly.

## Category status snapshot (as audited)

| Category | Maturity | One-line reality |
|---|---|---|
| Zero Trust (ZTNA) | ~45% | Real client-cert access broker + microseg + posture/risk policy inputs; posture **self-reported**, OIDC **unwired**, one credential, no client. |
| DLP | ~35% core | Strong sandboxed detection core; **observe-only in prod** (no enforcers wired), one channel, no EDM/OCR/ML, no endpoint enforcement/coaching. |
| NIPS / NTPS | ~15% | Forward-proxy egress DLP + opt-in TLS interception. **Not an IPS**: no inline/transparent, no signatures/threat-intel, request-body only. |
| SIEM | ~15% | Alert `/search` (D103), correlation→incidents (D104), case workflow w/ four-eyes (D105/D107), syslog ingest+listener (D106/D108) all landed. Still missing: *event* search (telemetry is opaque BYTEA), persisted incidents/rules, cross-host key, external formats beyond syslog, UI. |
| HIPS | 0% | Unbuilt. No exec producer, no behavioral classifier, no exec-control actions. |
| NAC | 0% | Absent. Posture-as-policy-input ≠ network admission control. Off-pipeline (see T4). |
| VPN | 0% | Absent. No tunnel. "Zero-Trust VPN" is a mislabel for the ZTNA proxy. Off-pipeline (see T4). |

**Crown jewel (protect it):** the per-agent forward-secure hash-chained ledger + external
anchoring is real end-to-end and is the platform's strongest asset. Several Bucket-S items
exist to keep it honest — do not regress it.

## T4 — the fourth tension: categories that do NOT fit the frozen pipeline

The three tensions above (T1 action-set, T2 risk-loop, T3 DLP-vs-XDR) all live *inside* the
pipeline bet. The Round-30 target list adds a harder one. **NAC and VPN are network-infrastructure
products, not data-security-pipeline capabilities.** They produce no classifiable Event and
consume no `Decision`:

- **NAC** is admission control at L2 (802.1X/RADIUS, VLAN assignment, switch/AP integration) —
  it decides whether a device gets *on the network at all*, before any traffic reaches a
  connector. There is no Event→Classify→Policy→Decision shape here.
- **VPN** is an encrypted L3/L4 tunnel + client. The ZTNA access proxy gives *application-layer*
  reachability to catalogued HTTP services; it cannot carry arbitrary L3 traffic and is not a VPN.

**Decision required from the owner (do not let the worker guess):** for NAC and VPN, either
(a) build them as **separately-scoped products beside the pipeline** (they reuse the PKI/identity
and can *feed* posture/risk into it, but they are not pipeline plugins), or (b) **drop them from
the category claims** and market ZTNA as the access story. The recommendation is **(b) for now** —
a credible DLP + ZTNA is worth more than shallow NAC/VPN — with the tickets below (`NAC-*`,
`VPN-*`) recorded as greenfield bets, not default trajectory. **Until the owner decides, the
worker must not begin `NAC-*`/`VPN-*`.**

---

## Bucket S — Security & correctness bugs  (do these first)

These are in code that already runs. Most are S/M. Fix before feature work.

**SEC-1 · Sign & verify the risk and posture NATS channels** — P0 · bug · effort M
- Problem: `SubscribeRisk` / `SubscribePosture` decode with a bare `proto.Unmarshal` and no
  signature check, unlike the Ed25519-signed + monotonic-sequence telemetry path. Anyone able
  to publish to `openshield.v1.risk` / `openshield.v1.posture` (any enrolled agent, or anyone
  past broker mTLS) can forge `risk=0` or `Compliant=true` for **any** subject.
- Impact: defeats ZT continuous-verification step-up/deny (D89) **and** the D85 device-posture
  tamper-lockout — i.e. the security core of the one category (ZT) that actually works.
- Evidence: `internal/gateway/risksub.go` (`SubscribeRisk`), `internal/gateway/posture.go`
  (`SubscribePosture`), `ApplyRiskUpdate`/`ApplyPostureUpdate`; contrast
  `internal/transport/nats/signed.go` (signed telemetry).
- Fix (split by producer — they have different key authorities): **risk** is published by the
  control plane (`internal/gateway/riskpub.go` / `controlplane`) → verify against the
  **control-plane** key. **posture** is meant to be agent-self-reported → verify against the
  **agent** key, with the update's subject bound to the signing agent's own identity (a compromised
  publisher must not forge *another* subject's posture). Both: wrap in the existing signed-envelope
  type, verify **before** `store.Set`, drop + count unverified (mirror telemetry `Gaps`/verified).
- Sequencing: uses existing provisioning/enrollment key material — **does NOT wait on PLAT-3.** Do
  the **risk** half first; the **posture** half can only be tested once a signed posture producer
  exists (HON-4 — today the posture channel has zero publishers).
- Verify: unit test publishes a validly-signed update (applied) and a tampered/unsigned/wrong-key
  update (rejected, counted); mutation "skip signature check" must fail the test. The negative
  case must reach real verification, not a routing short-circuit.
- Blocks: ZT integrity.

**SEC-2 · Enrollment cannot overwrite an existing agent's key or un-revoke** — P0 · bug · effort S
- Problem: `Enroll` uses `ON CONFLICT (agent_id) DO UPDATE SET public_key = …, revoked_at = NULL`.
  Any valid fresh enrollment token can overwrite **any** existing agent's public key and
  **un-revoke a revoked agent**, then sign "verified" telemetry as that agent (replay guard is
  moot — pick a large sequence).
- Evidence: `internal/controlplane/identity.go` (`Enroll`, the `ON CONFLICT` clause).
- Fix: refuse enrollment for an `agent_id` that already exists or is revoked (return conflict);
  or bind token→agent_id at issuance so a token can only enroll its designated id. Re-enrollment
  becomes an explicit, audited operator action, never an implicit upsert.
- Verify: test that a second enroll for an existing id is rejected; that a revoked id stays
  revoked; that the previous key still verifies and the attacker key does not. Mutation "restore
  DO UPDATE" fails the test.

**SEC-3 · Dead-man's-switch & operator views must count only verified telemetry** — P0 · bug · effort S
- Problem: `Overdue` / `LastSeen` (and `/view`) aggregate `fleet_telemetry` without filtering
  `verified`, and the unsigned `events/classifications/decisions/heartbeats` subjects are still
  subscribed with a self-asserted `agent_id`. A dead/compromised agent can be kept "alive"
  indefinitely by anyone who can publish, and unverified rows pollute operator views.
- Evidence: `internal/controlplane/heartbeat.go` (`Overdue`, `LastSeen`),
  `internal/controlplane/controlplane.go` (unsigned subscriptions), `views.go`.
- Fix: derive liveness and views from `verified = true` rows only; deprecate/remove the unsigned
  ingest path (or quarantine it to a clearly non-authoritative table). Also LEFT JOIN the roster
  from `agent_identities` so an enrolled-but-silent or post-purge agent still surfaces as overdue
  (today it never appears / drops off after purge).
- Verify: test that unsigned heartbeats do not reset `LastSeen`; that an enrolled-then-silent
  agent appears overdue; that a purged long-silent agent stays flagged.
- Sequencing: SEC-3 decides the fate of the unsigned ingest path **before** SEC-4 instruments those
  same `conn.Subscribe` handlers, and **absorbs SEC-11's `LastSeen` error-vs-absence fix** (same
  function). Do SEC-3 → SEC-4.

**SEC-4 · No silent server-side telemetry loss** — P0 · bug · effort S
- Problem: NATS subscribers do a synchronous DB insert per message with **no `SetPendingLimits`
  and no `ErrorHandler`** anywhere. A slow consumer overflows the client buffer and drops
  messages **silently and uncounted** — violating the project's own "no silent loss" invariant
  on the receive side (the send side has spool + gap detection; the receive side does not).
- Evidence: `internal/controlplane/controlplane.go` (`conn.Subscribe` handlers); no
  `SetPendingLimits`/`ErrorHandler` in `internal/transport/nats`.
- Fix: set explicit pending limits, install an async `ErrorHandler` that counts + loudly logs
  `SlowConsumer`/drops, and expose the counter (see PLAT-4 metrics). Prefer moving ingest to
  JetStream durable consumers with ack (PLAT-2), which removes the drop window entirely.
- Verify: an integration test that floods a throttled subscriber asserts the drop counter is
  non-zero and logged (no silent zero). Mutation "swallow the error handler" fails it.
- Alias: subsumed by PLAT-2 (JetStream) if that lands first. Do the pending-limits/`ErrorHandler`
  stopgap now regardless; don't build it twice.

**SEC-5 · Tombstone/purge must not be able to destroy evidence undetectably** — P1 · bug · effort M
- Problem: append-only trigger (migration `010`) permits any `UPDATE` that sets `tombstoned_at`
  while rewriting content columns — that is how `Purge` works, so **any SQL principal can
  tombstone any row, including `RetentionInvestigation` (legal-hold) rows, and `VerifyChain`
  still reports the chain Consistent.** The purge itself appends no ledger entry, so destruction
  is unattributable. Enterprise legal-hold posture fails here.
- Evidence: `internal/store/postgres/migrations/010_*.sql` (trigger), `internal/store/postgres/`
  (`Purge`), `internal/core/ledger.go` (`VerifyChain` treats tombstone as consistent).
- Fix: (a) a DB trigger **cannot** read Go-side retention ages (`core.RetentionClass.MaxAge()`), so
  scope the trigger to a *class* check it CAN enforce — **never permit tombstoning
  `retention_class = investigation`** (legal hold) — and keep age enforcement in `Purge`. (Persist
  retention policy in a DB table the trigger reads only if age-in-DB is later wanted.) (b) every
  purge/tombstone appends its own audit entry (who/when/policy) so destruction is attributable and
  chain-visible. Pairs with SEC-6.
- Blocked-by: the legal-hold test needs something that *sets* `retention_class = investigation`;
  nothing does today (see HON-2). Either seed it directly in the test, or land HON-2's
  case→legal-hold wiring first.
- Verify: test that tombstoning a legal-hold row is rejected at the DB layer; that a lawful purge
  appends an audit entry; that `VerifyChain` distinguishes lawful tombstone from content rewrite.

**SEC-6 · Ship the non-owner ledger DB role** — P1 · bug · effort S
- Problem: migration `010`'s own comment says the complete fix is running the ledger under a
  **non-owner restricted role** (an owner can disable the trigger). No `GRANT`/`REVOKE`, role, or
  deploy wiring exists, and the shipped DSN uses the owner — so DB-level append-only is currently
  advisory against a leaked owner credential.
- Evidence: migration `010` comment; absence of role/GRANT in `deploy/` and `scripts/`; DSN in
  `compose.yaml`.
- Fix: add a migration creating a restricted `openshield_writer` role (INSERT + permitted
  tombstone UPDATE only, cannot ALTER/disable triggers); run the app under it; owner role reserved
  for migrations. Document the split.
- Verify: test that the writer role cannot `ALTER TABLE … DISABLE TRIGGER` and cannot `DELETE`;
  that migrations still run under the owner.

**SEC-7 · Prefilter prefix read must use the no-follow safe reader** — P2 · bug · effort S
- Problem: the inline prefilter's bounded prefix read uses `os.Open`, not
  `safeio.ReadRegularNoFollow` — inconsistent with the TOCTOU discipline the enforcers already
  hold (D65). Lower severity (it's unwired today), but close it before Phase B wires inline.
- Evidence: `internal/agent/prefilter/decider.go` (`openFile`/`os.Open`); contrast
  `internal/enforcers/safeio`.
- Fix: route the prefix read through `safeio` (O_NOFOLLOW + refuse-non-regular).
- Verify: test that a swapped symlink prefix is refused (mirror the enforcer safeio tests).

**SEC-8 · Operator search input validation** — P2 · bug · effort S
- Problem: `/search` silently drops malformed `since`/`until`/`min_risk` (→ over-broad results
  that look authoritative) and `limit` has no upper bound (unbounded result / memory).
- Evidence: `internal/controlplane/operator_read.go` (filter parse; `limit`).
- Fix: 400 on malformed filter params; cap `limit` (configurable max). (SQL injection itself is
  already correctly parameterized — verified; do not regress that.)
- Verify: test malformed params → 400; oversized limit → capped; the existing injection test
  stays green.

**SEC-9 · Access-proxy header hygiene + trustworthy identity header** — P2 · bug · effort S
- Problem: the access reverse proxy forwards the original client request without stripping
  client-supplied identity/forwarding headers (`X-Authenticated-User`, `X-Forwarded-*`), and it
  injects **no** trustworthy verified-subject header — so a backend can be fed a spoofed identity
  and cannot consume the real (pseudonymous) one. Hop-by-hop stripping exists on the egress path
  only.
- Evidence: `internal/gateway/access.go` (forward), `internal/gateway/catalog.go`
  (`NewSingleHostReverseProxy`); contrast `copyHeader`/`hopHeaders` in `proxy.go`.
- Fix: strip inbound identity/forwarded headers; inject a signed or gateway-authoritative
  `X-OpenShield-Subject` (the pseudonym) for backends. Also normalize `SrcIP` (access path stores
  `host:port`, egress splits it — `access.go`).
- Verify: test that a client-sent `X-Authenticated-User` never reaches the backend and the
  injected subject matches the verified cert pseudonym.

**SEC-10 · Persist restart-fragile in-memory state** — P2 · bug · effort M *(also SIEM-relevant)*
- Problem: `notifiedOverdue`, `peerLastAlert`, and the peer-UEBA baselines + `context_version`
  counter are in-memory only. Server restart re-pages every overdue agent and every anomalous
  subject, and the `ctx-N` version strings collide across restarts — breaking D27 attribution of
  which context a decision saw.
- Evidence: `internal/controlplane/notify.go` (`notifiedOverdue`), `controlplane` (`peerLastAlert`),
  `internal/analytics/peerueba/peerueba.go` (baselines, version counter).
- Fix: persist dedup/cooldown state and the context-version counter (Postgres or a durable KV);
  make `context_version` monotonic across restarts.
- Verify: test that restart does not re-emit an already-notified overdue/anomaly and that
  `context_version` never repeats.

**SEC-11 · Error-vs-absence honesty in counters/lookups** — P2 · bug · effort S
- Problem: `LastSeen` swallows all DB errors as "agent unknown" (a down DB reads as agent
  absence); telemetry/peer-alert **insert** failures increment `DecodeFailures` (a down DB
  masquerades as malformed input — the only observability counter lies). Both are the recurring
  "verifies against its own assumptions" shape.
- Evidence: `internal/controlplane/heartbeat.go` (`LastSeen` error path),
  `internal/controlplane/signed.go` (`DecodeFailures` on insert error).
- Fix: distinguish infrastructure error from absence/malformed; separate counters
  (`decode_failures` vs `store_failures`); surface DB-down as an error/health signal, not absence.
- Verify: test that a DB error yields an error (not "unknown"/"decode failure").

---

## Bucket H — Honesty reconciliation  (claim vs reality — the brand)

These are places where a committed/"done" feature is dead code, vaporware, or unwired. The
project's entire brand is honesty about limits; either wire them or downgrade the claim.

**HON-1 · Load signed custom detector rules in the worker** — P1 · wiring · effort S–M
- Problem: `LoadSignedRules` / `WithRules` (the D100/D3 "admin-authorable signed rules" feature,
  committed as "Phase D complete") are never called by any binary — the worker builds a bare
  `classify.New()` (built-ins only). The feature is unreachable in production.
- Evidence: `cmd/openshield-worker/main.go` (`classify.New()`), `internal/classify/rules.go`
  (`LoadSignedRules`/`WithRules` — no callers).
- Fix: worker loads a signed rule bundle from a configured path, verifies against the trusted
  operator key (fail-closed, all-or-nothing per the existing design), and merges via `WithRules`.
  Keep the path-vs-content and no-leak (`DETECTOR_TYPE_CUSTOM`) guarantees intact.
- Verify: binary-level test — a signed bundle on disk causes a custom detector to fire through the
  real worker; a tampered/unsigned bundle loads nothing and the worker still starts with built-ins.

**HON-2 · Wire case-open → legal-hold (the case workflow itself LANDED)** — P1 · wiring · effort S
- Status update: the case workflow is **now implemented** — `internal/controlplane/cases.go`
  (D105/D107) does open/assign/note/four-eyes close (`ErrFourEyes`) + incident→case linking, with
  tests. The original "011 is vaporware" finding is **stale — do not re-implement it.**
- Residual true gap: **nothing sets `retention_class = investigation` (legal hold)** — grep finds no
  setter outside `internal/core`. So opening a case does not actually hold its linked evidence, and
  SEC-5's legal-hold guarantee has nothing to protect.
- Fix: on case-open (or evidence-link), flip the linked ledger rows to the investigation retention
  class; optionally release on close. This is the setter SEC-5 depends on.
- Verify: e2e — opening a case + linking evidence flips those rows to legal-hold; a subsequent purge
  (past normal age) does NOT tombstone them, and SEC-5's trigger refuses to.

**HON-3 · Wire enforcement into the endpoint engine** — P0 · wiring · effort S
- Problem: the production engine registers **zero enforcers** (`Enforcers` slice empty;
  `NewFromWorker` never populates it), so despite quarantine/encrypt/USB enforcers + the two-tier
  inline prefilter + watchdog being built and unit-tested, production is observe-only and nothing
  can contain anything. `README` says "observe-only default" but the enforcers aren't even
  *registrable* in the running binary.
- Evidence: `internal/engine/engine.go` (empty `Enforcers`), `cmd/openshield-engine/main.go`
  (registers none); enforcers in `internal/enforcers/*`.
- Fix: register the file enforcers behind `OPENSHIELD_ENFORCE` (mirror the gateway's opt-in flow
  enforcer), observe-only default preserved. This is the prerequisite that makes Phase B
  (inline prevention) and DLP containment *mean* anything.
- Verify: binary-level e2e — with `OPENSHIELD_ENFORCE` set and a QUARANTINE policy, a seeded CPF
  file is actually moved + audited; without the flag, observe-only (decision recorded, file
  untouched).

**HON-4 · A signed device-posture producer** — P1 · new producer · effort M
- Problem: the posture channel (`PostureStore` / `SubscribePosture`, D92) has **no publisher
  anywhere in the repo** — nothing ever emits a `PostureUpdate`. The D85/D92 tamper-lockout can
  therefore never see real data: absent posture fails closed, so a posture-gated policy denies
  everyone (or is never exercised). Claimed-but-unwired — the Bucket-H shape.
- Evidence: repo-wide grep — `PostureStore.Set` / `ApplyPostureUpdate` have subscribers, zero
  producers; contrast risk (`riskpub.go` exists).
- Fix: an endpoint-agent producer that reports device posture, **agent-key-signed** with subject
  bound to its own identity (this is the producer SEC-1's posture half verifies). Self-report is
  only as trustworthy as the reporter — ZT-1 (attestation) is the hardening; absent-posture
  fail-closed still catches a silent endpoint.
- Verify: e2e — a running agent publishes signed posture, the gateway applies it, and a
  forged/unsigned posture for another subject is rejected (SEC-1).

---

## Bucket P — Platform & enterprise operability  (gates every category)

**PLAT-1 · A UI** — P1 · new work · effort XL — *the single biggest enterprise-credibility gap.*
- Minimal SPA (or rich TUI first) over the existing operator-read API: fleet health, alerts,
  incidents, search, agent status, case workflow. No UI exists at all (F4 deferred). The read/search
  APIs (D82/D103) are its substrate. Fits above the pipeline; needs a frontend toolchain decision
  (the repo is pure Go today).

**PLAT-2 · Durability & HA: JetStream + no single points of failure** — P1 · new work · effort M–L
- Move agent telemetry ingest to **JetStream durable consumers with ack** (today it is core NATS
  fire-and-forget → at-most-once; loss is *detected* via sequence gaps but *unrecoverable*, and the
  agent spool only covers *broker-unreachable*, not *broker-up/server-down*). This also closes SEC-4.
  Then address single server / single Postgres / single NATS and the per-message `FOR UPDATE` lock +
  DB round-trip that hard-serializes ingest (`VerifySigned`). Add backpressure signalling to agents.
- Evidence: `internal/transport/nats/nats.go` (documents core-NATS), `signed.go` (`storeOrSend`,
  `VerifySigned` row lock).

**PLAT-3 · Multi-tenancy + analyst RBAC** — P1 (RBAC) / P2 (tenancy) · new work · effort M (RBAC) / XL (tenancy)
- No tenant concept anywhere (no org column, no partitioning) and exactly two cert-OU roles
  (`agent`/`operator`) — no analyst tiers. Add per-route RBAC tiers (read-only analyst vs responder
  vs admin) on the `requireRole` seam first (M); org/tenant isolation is a larger XL effort tied to
  the managed-Hub open-core boundary (`internal/enterprise`). Also provides the message-signing key
  authority SEC-1 needs.

**PLAT-4 · Metrics & observability** — P1 · new work · effort M
- No Prometheus/OTel/`/metrics` anywhere. Add a metrics endpoint + counters (telemetry
  verified/dropped/gap, ingest rate, ledger append rate, enforcement outcomes, slow-consumer drops
  from SEC-4). Note: OTel was consciously cut from Phase 1 (brief) — this is a deliberate re-opening
  for enterprise operability, flag it as such in the change.

**PLAT-5 · Config management beyond env vars** — P2 · new work · effort S–M
- ~14 files read `os.Getenv` and there is no config-file loader. Add a typed config
  (file + env override), validated at boot with fail-fast/loud errors (the gateway already models
  this). Keeps secrets as file paths, not inline.

**PLAT-6 · Release, packaging & deploy** — P2 · new work · effort M
- `VERSION=0.1.0-pre`, no git tags, no goreleaser, no Helm/k8s manifests, hand-rolled migration
  runner. Add tagged releases + reproducible binaries (goreleaser), signed artifacts (reuse the
  provisioning/anchor signing culture), and at least a documented container/systemd deploy path
  (systemd units exist; k8s/Helm is the enterprise ask). Keep the open-core boundary
  (`internal/enterprise`, `internal/packaging`) intact.

**PLAT-7 · Cross-platform producers/enforcers (Windows/macOS)** — P1 for real-world DLP · external-gated · effort XL
- Already in the roadmap (external gating: Windows EV cert + attested minifilter; macOS Endpoint
  Security entitlement). The core is portable (all-Go); producers/enforcers are per-OS. **Most
  enterprise data lives on Windows** — this gates real-world DLP relevance more than any single
  feature. Sequence independently once ecosystem gating is resolved.

**PLAT-8 · DSAR / privacy-operations surface** — P2 · new work · effort M
- Retention/tombstoning + pseudonymisation + the UEBA consent/DPIA gate are real (better than most
  at this stage), but there is no DSAR export, no legal-hold *trigger* (nothing sets
  `RetentionInvestigation` — see HON-2), and retention windows are env vars, not auditable policy.
  Add a DSAR/export path and make retention policy auditable.

---

## Feature backlog by category  (extends Phases A–F)

Each item notes pipeline fit (P/C/X/A = producer/classify/context/action; or off-pipeline) and effort.

### Zero Trust / ZTNA  (extends Phase A — the closest-to-credible category)
- **ZT-1 · Hardware device-posture attestation** — P1 · X + new producer · XL (sequenced by the
  revised order, **not** first-tier). Today posture is self-reported booleans; a compromised-but-alive
  agent signs `Compliant=true` (SEC-1 only fixes third-party spoofing, not owner-lying). Add
  TPM/measured-boot signed quotes verified at the gateway. (`google/go-tpm` is only an `// indirect`
  dep today — an artifact, not readiness; treat TPM as greenfield.) Builds on HON-4's posture
  producer. This is the ZTNA-vs-toy line.
- **ZT-2 · Wire the OIDC/JWT verifier** — P1 · already-built, needs wiring · S (wire) / M (live JWKS).
  `identity/oidc.go` is complete and well-tested (rejects `none`/alg-confusion) but **no binary
  constructs it**. Wire it into the access proxy; add live JWKS discovery as a conscious,
  gateway-chokepoint-aware addition. Enables SSO.
- **ZT-3 · Dual-credential (user token + device cert)** — P1 · X · M. BeyondCorp presents both;
  compose ZT-2 identity with ZT-1 device posture in one authorization.
- **ZT-4 · ZTNA client/connector model** — P2 · new work · L. Enterprise ZTNA is agent-brokered;
  today it is server-side reverse-proxy only.
- **ZT-5 · Policy admin + session recording** — P2 · new work · L. Policy is a boot-loaded file;
  add an admin surface (ties to PLAT-1) and per-session audit/recording.
- **ZT-6 · SAML** — P3 · new producer · L. Only after OIDC (ZT-2) proves the SSO seam.

### DLP  (extends Phase D + enforcement)
- **DLP-1 · Wire endpoint enforcement** — _alias, canonical is HON-3 (P0)_. Prerequisite for
  containment meaning anything. Do not double-propose.
- **DLP-2 · Real exfiltration-channel producers** — P0-for-product · new producers (+ maybe actions) · XL, per-OS.
  Clipboard, print, screenshot, removable-media file-copy (content-aware, not the current global USB
  on/off), cloud-sync/CASB. A DLP that watches directories but not the channels users exfiltrate
  through is not a DLP. Mostly pipeline-fit as producers; some need new typed actions (T1).
- **DLP-3 · EDM / IDM / OCR** — P1 · classify (server-side) · XL. Exact-data-match ("this customer
  DB"), document fingerprinting, OCR for image-borne data. **Architectural tension:** D10/D11 forbid
  hash/fingerprint leaving the endpoint, so EDM/IDM must be server-side or an opt-in worker plugin —
  design it there, do not break the boundary.
- **DLP-4 · Incident/case workflow** — ✅ mostly **LANDED** (D105/D107); residue = legal-hold wiring
  (HON-2). _Alias — do not re-propose._
- **DLP-5 · Compliance policy packs** — P1 · classify + policy · M. PCI/HIPAA/GDPR templated Rego +
  detector sets (today one hand-written `default.rego` that only ALERTs on CPF/credit-card).
- **DLP-6 · Endpoint user coaching/justification** — P1 · X + UI · M. REDIRECT-to-coaching exists at
  the network gateway only; bring justification/coaching to the endpoint.
- **DLP-7 · Detection breadth** — P1 · classify · M–L. Phone (enum exists, no detector), passport /
  national-ID beyond CPF, driver's license, keyword-proximity/context rules. Ships via HON-1's signed
  custom-rule surface + built-ins.
- **DLP-8 · Format depth** — P2 · classify · M. Nested-archive recursion (stops at one level today),
  RTF / legacy `.doc` binary, response-body multipart/gzip (shared with NIPS-4).

### NIPS / NTPS  (extends Phase C — makes the gateway a real data plane)
- **NIPS-1 · Transparent/inline connector** — P0 · new data-plane (D) · L. TPROXY/nftables redirect or
  L2 bridge feeding the same pipeline, removing the "clients must be configured to proxy" limit. Likely
  external-gated (needs root/CAP_NET_ADMIN) like B2 — confirm empirically and record.
- **NIPS-2 · Signature / threat-intel engine** — P0 · classify plugin (C) · L. Suricata/Snort-ruleset
  or YARA-style network classifier + IOC feeds. Without this it is categorically not an IPS.
- **NIPS-3 · Wire the DNS & SMTP parsers to live listeners** — P1 · new connector topology · M. The
  hard part (untrusted-bytes parsing) is built and tested (`connectors/dns`, `connectors/smtp`); only
  the socket front-end (a UDP:53 resolver / SMTP session listener → `ToEvent` → pipeline) is missing.
  Highest-leverage next network step. Unlocks DNS-exfil/C2 detection (the `TunnelScore` heuristic
  exists but is unwired) and email DLP end-to-end.
- **NIPS-4 · Response-body inspection** — P1 · classify · M. Today only the *request* body is
  classified; the response is copied through — exfil-via-download and malware delivery pass
  unclassified. Add buffered/streamed classification with memory bounds, gzip + multipart decode
  (shared with DLP-8), and define response-direction fail-open. **Must preserve the deliberate
  D73/D17 egress fail-open** — do not "fix" it into fail-closed.
- **NIPS-5 · HTTP/2 & QUIC interception** — P2 · new work · L. Modern traffic tunnels blind today
  (HTTP/1.1 only).
- **NIPS-6 · Raw TCP/L4 metadata connector + anomaly/beaconing detection** — P2 · P + C · L.

### SIEM  (extends Phase F — currently ~5%)
- **SIEM-1 · Typed/JSONB *event* storage + `/events` search** — P1 · pipeline extension · L. Today
  `fleet_telemetry` payloads are opaque proto `BYTEA` — field-level queries are impossible and there
  is nothing to hunt in. Decode to typed columns / JSONB at ingest, index, add an `/events` search
  endpoint (extend the parameterized, injection-safe pattern in `operator_read.go`). _(Note: alert
  `/search` over `peer_alerts` already landed — D103; this is the missing **event** search over
  telemetry, a different and larger surface.)_
- **SIEM-2 · Persist & broaden correlation** — P1 · pipeline extension · L. _[partly landed]_ A
  burst-rule correlator + incident→case conversion landed (D104/D107, `correlate.go`), but incidents
  are still **computed-on-read** (no `incidents` table; migrations end at 011) and `peer_alerts`
  (009) has **no `agent_id`/host column**, so cross-host correlation is impossible by schema. Build:
  persisted incidents (IDs/state), a real multi-rule engine (threshold/sequence over typed fields),
  and the `agent_id` column. **Do NOT rebuild the correlator that exists.**
- **SIEM-3 · Case/investigation workflow** — ✅ **LANDED (D105/D107)** (`internal/controlplane/cases.go`).
  _Alias of HON-2_ — the only residue is the legal-hold wiring tracked there. Do not re-propose.
- **SIEM-4 · External log ingestion (beyond syslog)** — P1 · new connector class · M. _[partly landed]_
  A syslog parser + UDP listener landed (D106/D108, `internal/connectors/syslog/`). Remaining: CEF /
  WEF / cloud-JSON formats and wiring ingested logs into the **verified** ingest + search/correlation
  path (not just a listener). Effort drops from XL now the syslog precedent exists.
- **SIEM-5 · Persist + broaden UEBA** — P1 · analytics · M (persist, = SEC-10) / L (features). The
  z-score math is genuinely good but single-feature (event rate) and fully in-memory. Persist baselines;
  add per-kind rate / time-of-day / data-volume features via the Analyzer seam.
- **SIEM-6 · Alert lifecycle** — P1 · schema + API · M. Severity, ack/close, dedup key, status,
  alert-type on `peer_alerts` (today: no severity, no host, no status).
- **SIEM-7 · MITRE ATT&CK mapping** — P1 · classify metadata · M. Tag detections with techniques.
- **SIEM-8 · Notification robustness** — P1 · notify · S–M. Retry/backoff, multiple sinks,
  HMAC-signed webhook body (today: single best-effort webhook, no retry).
- **SIEM-9 · Threat-intel enrichment + saved searches/scheduled reports** — P2 · S–M / M.
- **SIEM-10 · Compliance/retention reporting** — P2 · M. What was purged, when, by which policy
  (ties to PLAT-8).

### HIPS  (Phase E — the explicit XDR fork, 0% today; only on the T3 platform bet)
- **HIPS-1 · Exec-event producer** — P0 · producer · L–XL. `FAN_OPEN_EXEC_PERM` (permission mode,
  needs CAP_SYS_ADMIN — same external gating + permission-window timing as B2), or eBPF-LSM, or auditd.
- **HIPS-2 · Behavioral classifier domain** — P0 · classify (new shape) · XL. Process lineage,
  allow/deny-list, LOLBin/signature-of-behavior — reasons over process metadata, not bytes. An ongoing
  detection-content commitment, not a one-time build.
- **HIPS-3 · `DENY_EXEC` / `KILL_PROCESS` actions** — P0 · action expansion (A, T1) · L each. Each a
  distinct typed verb with its own enforcer + guard (the D14 red line: never a generic "run command").
  Requires owner sign-off on T1.
- **HIPS-4 · FIM, memory/injection detection, ransomware canary, application whitelisting** — each a
  separate subsystem-sized bet · XL each. Do not bundle.

### NAC — off-pipeline greenfield (blocked on the T4 owner decision)
- **NAC-1 · 802.1X/RADIUS authenticator + switch/AP integration** — off-pipeline · XL.
- **NAC-2 · Posture-gated network admission + quarantine VLAN** — off-pipeline · XL.
- **NAC-3 · Guest onboarding / captive portal / agentless discovery** — off-pipeline · XL.
  *(All NAC-* are network-infrastructure, not pipeline plugins. They may reuse the PKI/identity and
  can feed posture into the ZT context, but they do not fit Event→Classify→Policy→Decision. Do not
  start until T4 is decided.)*

### VPN — off-pipeline greenfield (blocked on the T4 owner decision)
- **VPN-1 · Tunnel data plane (WireGuard or IPsec or TLS-tunnel) + client** — off-pipeline · XL.
- **VPN-2 · Split-tunnel policy + per-tunnel cert lifecycle** — off-pipeline · L.
  *(Greenfield; nothing in the frozen pipeline provides a tunnel. ZTNA is not a VPN. Recommendation
  stands: prefer dropping the VPN claim in favor of ZTNA unless the owner explicitly funds this.)*

---

## Revised suggested order (with the backlog folded in)

1. **Bucket S** (security) then **Bucket H** (honesty) — cheap, in working code, and they protect
   the categories already claimed. SEC-1/2/3/4 and HON-3 are the non-negotiable first tier.
2. **Finish making the claimed categories real:** ZT-1/ZT-2 (attestation + SSO) and DLP-1/DLP-5
   (wired enforcement + compliance packs), plus **PLAT-1 (a UI)** — this turns two ~40% categories
   into defensible products. In parallel, **PLAT-2/PLAT-4** (durability + metrics) because they gate
   enterprise adoption more than feature breadth.
3. **Broaden:** NIPS-3 (wire DNS/SMTP listeners), NIPS-1/2 (inline + signatures), SIEM-1 (event
   search) + SIEM-2 (persist correlation + cross-host key) + SIEM-4 (CEF/WEF/cloud ingest),
   DLP-2/DLP-3 (channels + EDM). _(SIEM-3 / case workflow already landed — D105/D107.)_
4. **XDR fork (only on the T3 bet):** Phase E / HIPS-*.
5. **Cross-platform (PLAT-7)** runs alongside, externally gated — highest real-world DLP leverage.
6. **NAC / VPN:** do not start; return to the owner for the **T4** build-vs-drop decision first.
