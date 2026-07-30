# Changelog

All notable changes to OpenShield. This project records its reasoning in
[`docs/decisions.md`](docs/decisions.md) (the architectural decision register,
referenced below by `Dxx`); this file is the milestone arc in build order. From
D305 most `Dxx` handles are commit handles — `git log` holds the detail, and
[`docs/architecture-roadmap.md`](docs/architecture-roadmap.md) holds live status.

The format is loosely [Keep a Changelog](https://keepachangelog.com); the project
is pre-1.0 and every release is `0.x`. Nothing here is a stability promise.

## [Unreleased]

**Pre-alpha; no release has been cut.** The tooling to cut one exists — reproducible
builds, a signed manifest, a signed SBOM and a verifier — and nothing has been
published with it.

Far more than the walking skeleton now runs. Detection and response span endpoint,
network and identity on one pipeline, with cross-domain correlation, incident
timelines, SOAR playbooks and coordinated containment above it. Inline prevention is
real and proven on a live kernel for both process execution and file opens. What
pre-alpha still means: **there is no analyst UI**, durability is single-node, the
product is Linux-first, and none of this has run in production anywhere.

### Foundations & the observe path (Phase 1)

- Protobuf Event/Decision contracts with a **closed, typed action set** and
  confidence-not-certainty; the enforcer interface cannot see classifier internals
  (compile-checked). (D3–D4, D14)
- Privilege-split endpoint DESIGN: an unprivileged network-capable engine (OPA +
  Postgres) and a **seccomp-sandboxed** parser worker — both built and running;
  plus a privileged agent (for future inline blocking) that never parses attacker
  bytes — deferred (D49). (D13, D29, D35, D48)
- Pattern classifier (regex + checksum: Luhn, CPF) emitting **type + confidence +
  count only** — no content, no reversible low-entropy hashes. (D10, D5)
- Local OPA/Rego policy evaluation → Decision. (D8, D34)
- Forward-secure audit ledger on Postgres: hash chain + key-evolving signatures —
  tamper-**evident** with forward integrity between external anchors, never
  tamper-proof (impossible in a single self-hosted trust domain). (D9/T-009, D30, D38)
- Real fanotify observe connector (NOTIFY mode, unprivileged). (D52)
- The `openshield-engine` **binary** runs the assembled observe path itself
  (watches `OPENSHIELD_WATCH_DIRS`, notify-mode fanotify → classifier → policy →
  Decision → ledger → ALERT), proven at the binary level (the integration suite),
  not only via package tests. Inline blocking (the privileged permission-mode
  agent) remains deferred (D49). (D62)
- Fail-open watchdog, parser-sandbox hardening, retention/purpose/exclusion
  privacy features, doc-consistency guard, open-core import boundary, external
  anchoring. (D17/D18, D35, D20/T-013, D37, D21, D38)

### Fleet & control plane

- Per-agent Ed25519 identity, single-use enrollment tokens (HTTP endpoint),
  signed telemetry with monotonic sequence + gap/replay detection, heartbeat /
  dead-man's-switch. (D44, D50, D51, D42)
- Control plane that verifies signed telemetry on ingest and persists a fleet
  aggregate (never the evidentiary ledger); observes, does not control. (D41, D14)
- Live multi-agent fleet simulation across real Podman containers. (D51)

### Analytics

- Server-side **peer-baseline UEBA** over the verified fleet stream — stateful,
  cross-entity risk relative to peers, off by default, produces investigations
  without controlling agents. Confirmed the D26 fitness claim: a new-shape
  capability needed exactly one small core seam (`Dispatcher.ResolveContext`).
  (D53, D54)

### Transport & access security

- **Mutual TLS** on the agent-facing channels (enrollment + telemetry), layered
  beneath Ed25519 signing (both enforced); opt-in, fail-closed, no plaintext
  downgrade. (D55)
- **Authenticated operator identity** for the view-audit: the viewer is bound to a
  verified client certificate (`operator:<CN>`), not a self-asserted string. (D56)
- **Certificate role authorization**: `/view` requires the operator role, `/enroll`
  the agent role, read from the verified cert OU; wrong role → 403, no cert → 401.
  (D58)

### Enforcement (post-decision, observe-only by default)

- Enforcement dispatch: the engine records a Decision, then dispatches to a
  registered enforcer and audits the outcome (failure is high-severity, never
  silent). Containment after detection, not prevention. (D49)
- Enforcers: quarantine (move), USB (attach-time allow/deny), and **encrypt-local**
  — AES-256-GCM in place, atomic, idempotent. (D39, D20-adjacent, D57)
- Encrypt-local **key escrow**: public-key (Curve25519 sealed-box) mode where the
  endpoint holds only the recipient public key and cannot decrypt what it seals;
  recovery needs the off-endpoint private key. (D59)

### Detection depth — DLP (Phase D)

- Exact-data matching (single- and multi-cell) and document fingerprinting (IDM),
  loaded from **signed indexes** — an index whose signature does not verify stops the
  worker rather than silently matching nothing. (D193, D197, D198, D204/ADR-9)
- Detector breadth: CPF, card/Luhn, SSN, phone, EIN, NPI, routing, SIN, NHS,
  passport, DL, Aadhaar, NINO — all honoring the D10/D11 content boundary.
- Exfil-channel awareness, keyword proximity, recursive archive extraction, and a
  content-aware CASB that blocks sensitive uploads to unsanctioned clouds.
  (D194, D214, D222)
- Compliance packs **compose** rather than replace, under a most-restrictive-wins
  lattice over data-plane verbs only — a compliance pack can never escalate to
  killing a process. (D171, ADR-5)

### Network data plane — gateway, NIPS/NTPS

- TLS-intercepting gateway: inline DLP over HTTP, each request classified in the
  sandboxed worker; response-body inspection (observe-only). (D69, D200)
- **Transparent inline prevention (NIPS-1):** TPROXY drops and splices L4 by
  destination IP, SNI or payload content-signature, self-installing and self-healing
  its rules — VM-proven on a real kernel. Egress **fails to wire, never fails the
  network closed** (ADR-8, D73/D17). (D225-D239)
- Threat-intel IOC engine and content-signature engine, both hot-reloading from a
  local file or a remote URL. (D192, D206, D209, D221)
- **DNS preventive sinkhole (NIPS-8):** NXDOMAIN resolver plus a transparent `:53`
  redirect (local and forwarded) with a mark loop-break and a self-healing bypass
  watchdog. (D231-D240)
- Live DNS-query and SMTP-message inspection into the pipeline, including
  DNS-tunnelling scoring. SMTP is captured and inspected, **not filtered**.
  (D341, D342)

### Endpoint depth — HIPS

- Full HIPS-4 suite: exec producer → behavioral classifier → `KILL_PROCESS`;
  trusted-identity critical-process guard with pid-reuse revalidation; FIM
  (baseline, real-time, signed, delete-aware); ransomware canaries; memory-injection
  W^X detection. (D174, D175, D223, D228, D229, D232, D233, D236)
- **Inline exec prevention on a live kernel:** static `DENY_EXEC` deny-list/whitelist,
  a `FAN_OPEN_EXEC_PERM` producer, and default-deny whitelisting. (D217, D224, D230)
- **The exec gate takes its verdict from the full pipeline** over a parser-free IPC
  bridge — the privileged binary still carries no protobuf parser, CI-enforced.
  (D244)
- **The inline file-open gate (B2):** the prefix is read from the descriptor the
  kernel already handed the agent — no second open, so no deadlock inside an
  uninterruptible window, and no TOCTOU. A second tier then classifies the whole file
  asynchronously, with a bounded path suppressor breaking the recursion. Both tiers
  fail open by design. (D352-D360)
- Endpoint exfil channels: clipboard **mediated** on X11 (the engine owns the
  selection and decides each paste by destination) and print jobs aborted in the CUPS
  filter chain before they print. Wayland stays observe-only — its protocol cannot
  identify a paste's destination. (D246, D247, D248)

### Zero Trust & identity

- **Full hardware attestation chain (ZT-1):** AK quote → EK→AK credential activation
  → measured-boot PCR policy → posture wiring → NATS transport → file and network
  self-enrollment → continuous re-attestation, swtpm-proven end to end. (D183-D191,
  D218, D314)
- One canonical device identity shared across enrollment, posture and the access
  proxy (IDENT-1/ADR-6); OIDC/JWT verification on-path with a live JWKS refresher;
  a dual-credential access proxy; RBAC analyst/responder/admin tiers. (D170, D179,
  D182, ADR-4, ADR-7)
- **ZTNA client (ZT-4):** an endpoint broker presenting the *device* certificate to
  the access proxy — loopback-only, refuses to start without an identity, never falls
  back to a direct connection. It brokers access; it does not prevent bypass.
  (D249, D251)
- **Operator identity (ZT-7):** the RBAC tier leaves the certificate and becomes
  revocable — resolved server-side per request, revocation is a row, and a database
  error denies rather than falling back. OIDC SSO where the token's claims do *not*
  decide the role, DPoP sender-constrained tokens, and SCIM deactivation.
  (D372-D380)

### SIEM & external log ingest

- Unified alert lifecycle — severity, status, dedup key, ATT&CK mapping, durable
  notification dedup, pruned UEBA baselines. (D172, D177, D178/ADR-10, D201, D207)
- `/events` and `/logs` search on the served TLS mux, operator-gated, with
  field-level JSONB hunting. (D212)
- External-log ingest: CEF over syslog, AWS CloudTrail, and Windows Event Forwarding
  XML. Syslog gained **TCP and mutual TLS**, because UDP could not lose an event
  visibly. (D202, D205, D208, D211, D279, D337)

### XDR — cross-domain correlation

- Entity graph wired and populated by real producers (device⋈user), with canonical
  subject stamping. (D195, D196, D203)
- An entity-keyed `unified_alerts` stream fed by **every** domain, via projection of
  each verified non-`ALLOW` Decision at ingest. (D213, D241)
- Cross-domain correlation — a distinct-domain window rule and an ordered
  domain-sequence rule grouped by entity, materialized per entity and paging once.
  (D242)
- **Incident timelines:** contributing alerts in detection order, each linked to its
  evidence with an explicit resolved / unresolved / derived state; reading one is
  view-audited. (D243)
- **Coordinated cross-domain response:** one signed, four-eyes-approved `CONTAIN` →
  the gateway blocks the entity's flows and the endpoint denies its execs, each by its
  own local policy, both stamping the same intent id. TTL expiry restores both.
  (D253, D254)
- Per-entity risk aggregation — MAX not sum, recency-weighted, published to every
  alias of the entity. (D255)

### SOAR — orchestration & response (ADR-12)

- Scheduled correlation on a leader-only clock; incidents carry a forward-only
  attributed lifecycle. (D220, D250)
- A generic four-eyes **approval object**, resolved atomically in the UPDATE
  predicate. (D251)
- **Playbook engine:** a trigger plus an ordered list of steps from a **closed,
  non-actuating registry refused at load**, with durable resumable run state that does
  not repeat a step across a restart. (D256)
- Signed threat-intel feed ingest — verification runs **before** the parser — into a
  shared IOC store, enriching incidents from observables the verified events already
  carry. (D257)
- Response metrics: detection latency, MTTA and MTTR kept apart, each reported with
  the population it excludes, and deliberately **never** aggregated per analyst.
  (D258)
- Notification routing by kind and severity to named sinks, first-match-wins; an
  unmatched notification goes everywhere and is counted, so a table with a hole
  over-notifies visibly rather than going silent. (D259)
- **Tier-2 signed Response Intents** — a closed, parameterless, TTL'd vocabulary
  consumed as typed policy context, gated on four-eyes and a blast-radius ceiling.
  (D252)
- **Tier-3 integration runners:** an IdP responder with a per-connector closed verb
  set and at-most-once claim — OpenShield's first action that **cannot be undone** —
  and bidirectional ITSM ticket sync with a closed set of remote statuses meaning
  closed. (D260, D261)

### Data-at-rest discovery

- **Object-store discovery (DSPM-1):** sweeps an S3-compatible bucket on an interval,
  reads a bounded prefix per object via a ranged GET, and feeds the same pipeline
  everything else feeds — content to the sandboxed worker, never onto the Event. No
  SDK; SigV4 hand-rolled over stdlib HMAC, so it works against MinIO/Ceph/R2 and the
  dependency tree is unchanged. The strongest test yet of the frozen-core claim: a
  genuinely new *producer shape* landed as a plugin. (D371)

### Platform & operations

- Durable ingest by default (JetStream, opt-out), all three producers switched
  through one helper, unavailable JetStream failing fast rather than silently
  degrading. (D180/ADR-2, D245)
- Active-passive HA via a Postgres advisory-lock leader lease. (D181/ADR-3)
- **Typed two-tier configuration:** fields declared once and used for both reading
  and describing, so the schema is derived rather than maintained beside the code.
  Bootstrap settings come from the environment; **dynamic settings are
  database-authoritative**, cluster-wide, with revisions, rollback and live apply.
  Secrets are a kind and are never readable back. All binaries declare their
  configuration, guarded tree-wide. (D262, D263, D272, D273, D274)
- **Signed, reproducible releases (PLAT-6):** `make release` builds every command
  reproducibly and emits a SHA-256 manifest with a detached signature plus a signed
  SBOM generated from the binaries; `make verify-release` re-checks every digest, the
  signature, the signer, and files present that the manifest does not name.
  Reproducibility is asserted by a test that builds twice. (D264, D276, D277, D339,
  D344)
- **Operational lifecycle (PLAT-9):** emergency fleet-wide disable that fails toward
  enforcing and is itself ledgered; verified restore (`restore-verify` treats "I
  cannot tell" as a failure); schema-skew reporting that warns and still starts;
  wire-version contract and upgrade order; a backup/restore drill run end to end
  against real `pg_dump`/`pg_restore`; and the operator runbook and deployment
  footprint. (D265-D271, D275, D277, D278)
- Broker lifecycle hardening: infinite reconnect with jitter (processes previously
  gave up after ~2 minutes), faster partition detection (~40s, previously ~4), and
  self-healing ingest when a broker returns with empty JetStream state. (D367-D370)
- Supply chain: a reachable `x/text` infinite-loop vulnerability fixed and
  `govulncheck` added to CI — the sophisticated half (reproducible builds, signed
  SBOM) had been built and the basic half skipped. 161 MB of stale executables
  untracked and guarded against. (D361, D363)

### Assurance — proofs, guards & CI

- **`INVARIANTS.md`:** five load-bearing invariants, each naming the test that fails
  when it regresses, each mutation-verified, each with its limit stated; a doccheck
  guard fails the build if a named test stops existing. (D298, D299)
- **Threat model extended to the platform:** eight trust boundaries, each naming the
  guard and the test that holds it, each stating its limit — including the
  uncomfortable ones. (D302)
- **Latency budget as a build gate:** the exec decision is measured on the real path
  and fails the build when p99 exceeds the IPC timeout. Writing it found that the
  engine-backed exec gate had **never denied anything** — events lacked provenance, so
  every decision errored and fail-opened while the logs said prevention was active.
  (D301)
- Fuzzing of the privileged parse surface — seven targets asserting termination and
  declared bounds — which found a `uint32`→`int` truncation bug at three sites and the
  fact that the suite had never run on a 32-bit architecture the agent compiles for.
  (D362)
- **The integration suite became a CI gate** — it had run in none, and is the only
  place `cmd/` wiring is exercised. `scripts/check-cmd-closure.sh` now guards the
  unwired-feature class tree-wide. Root-gated kernel tests for the open gate, the DNS
  redirect and the transparent inline plane are in a real-root CI job. (D365, D382,
  D389)
- **Coverage measured honestly:** two defects in the *measurement* were fixed first —
  the worker was killed before it could report (D381), and the privileged runs were
  not merged, understating the permission gate, exec gate and watchdog **4-7x**
  (D384). 71.1% at D384; the last full sweep read 78.1% and is published as a floor,
  not a grade. The campaign's yield was product bugs, not the number — see below.
  (D383-D417)

### Honesty & testing discipline

- Every guard is mutation-tested. Integration tests run against real Postgres and
  NATS (a cross-package advisory lock serializes their DDL) and against live
  containers. The doc-consistency guard rejects overclaiming language it is not
  allowed to promise.
  <!-- allow: doc-discussion -->
  The forbidden terms are, verbatim, `tamper-proof` / `prevents exfiltration` / `guarantees security`.
  Decisions carry explicit, honest caveats: host root defeats at-rest keys (D16);
  enforcement contains, it does not prevent; peer-UEBA and enforcement are off by default.
- **Two recurring defects were named rather than just fixed, because naming them produced
  a guard.** *The capability exists everywhere except at the point where its signal becomes
  a decision, and the logs report it working* — a DNS-tunnelling score with no caller, an
  SMTP connector no setting could turn on, a ZTNA client no binary built, a threat-intel
  match no policy read, an exec producer omitting provenance so every decision fail-opened.
  The durable output is `scripts/check-cmd-closure.sh`, a call-graph reachability check, not
  the individual fixes. (D300, D301, D341, D342, D348, D351, D365) · *A counter incremented
  by the right code and rendered by nothing* — five times, most seriously the pipeline's own
  timeout counter, which D17 calls the cheapest way to detect an adversary manufacturing
  fail-open bypasses; the gateway's forged-signature counters, where every `Rejected` read in
  the tree was in a test; and the emergency disable's own suppression count, which is the whole
  answer to "what did we not block during the incident". A rising rejection rate on a signed
  channel is the signal, not the noise. **Every atomic counter in the shipped tree is now read
  outside its own tests, and a fitness guard keeps it that way** — the durable fix for a defect
  found five times is a guard, not a fifth fix. (D348, D415, D417, D418, D419)
- **A test that passes for the wrong reason is the failure mode this project watches for.**
  Recorded instances include an assertion satisfied by TLS failing client-side rather than the
  server rejecting anything (D375), a gate assertion that passed for lack of privilege and
  would have failed on a rooted VM for a third unrelated reason (D399), a threshold derived
  from the code under test, and mutations that changed no observable behaviour and so proved
  nothing (D304, D400). Where a mutation could not fail, the mutation was fixed — not the
  test strengthened around it.
- **Writing the first test a package had ever had is the most reliable bug-finding signal in
  this codebase** — more so than low coverage. It found: quarantining two files with the same
  base name silently destroyed the first (D401), a CLI flag that set a subject to the literal
  string `"--event"` and printed an empty timeline (D397), a data race in shipped code (D392),
  a cancelled context taking thirty seconds to abandon enrollment (D409), and a PCR-list typo
  that narrowed attestation silently (D413).
