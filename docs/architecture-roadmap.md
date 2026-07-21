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
