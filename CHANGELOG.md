# Changelog

All notable changes to OpenShield. This project records its reasoning in
[`docs/decisions.md`](docs/decisions.md) (decision register, referenced below by
`Dxx`); this file is the milestone arc in build order.

The format is loosely [Keep a Changelog](https://keepachangelog.com); the project
is pre-1.0 and every release is `0.x`. Nothing here is a stability promise.

## [Unreleased]

Pre-alpha. The walking skeleton runs; there is no packaged release yet.

### Foundations & the observe path (Phase 1)

- Protobuf Event/Decision contracts with a **closed, typed action set** and
  confidence-not-certainty; the enforcer interface cannot see classifier internals
  (compile-checked). (D3–D4, D14)
- Privilege-split endpoint: a privileged fanotify agent that never parses
  attacker bytes, an unprivileged network-capable engine (OPA + Postgres), and a
  **seccomp-sandboxed** parser worker. (D13, D29, D35, D48)
- Pattern classifier (regex + checksum: Luhn, CPF) emitting **type + confidence +
  count only** — no content, no reversible low-entropy hashes. (D10, D5)
- Local OPA/Rego policy evaluation → Decision. (D8, D34)
- Forward-secure audit ledger on Postgres: hash chain + key-evolving signatures —
  tamper-**evident** with forward integrity between external anchors, never
  tamper-proof (impossible in a single self-hosted trust domain). (D9/T-009, D30, D38)
- Real fanotify observe connector (NOTIFY mode, unprivileged) wired end to end:
  kernel file event → classifier → policy → Decision → ledger → ALERT. (D52)
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

### Honesty & testing discipline

- Every guard is mutation-tested. Integration tests run against real Postgres and
  NATS (a cross-package advisory lock serializes their DDL) and against live
  containers. The doc-consistency guard rejects overclaiming language it is not
  allowed to promise.
  <!-- allow: doc-discussion -->
  The forbidden terms are, verbatim, `tamper-proof` / `prevents exfiltration` / `guarantees security`.
  Decisions carry explicit, honest caveats: host root defeats at-rest keys (D16);
  enforcement contains, it does not prevent; peer-UEBA and enforcement are off by default.
