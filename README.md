# OpenShield

An open-source **Data Security Platform**. DLP is the first capability built on it, not the
product itself.

> **Status: pre-alpha. The observe path runs as a binary; inline blocking is deferred.** On Linux,
> the `openshield-engine` binary runs the full observe path itself — it watches the configured
> directories (`OPENSHIELD_WATCH_DIRS`) with **unprivileged notify-mode fanotify**, classifies via
> the sandboxed worker, evaluates the OPA policy, decides, and appends to the forward-secure audit
> ledger. Proven end to end at the binary level (`deploy/observe-e2e.sh`: a real file dropped in a
> watched dir lands an ALERT in the ledger). Also built: a fleet control plane (per-agent identity,
> signed telemetry, enrollment, dead-man's-switch), server-side peer-UEBA, mutual-TLS transport with
> cert-role authorization, and post-decision enforcers (quarantine, USB, encrypt-local with key
> escrow) that are **observe-only by default**. **Deferred:** *inline blocking* (the privileged
> permission-mode agent) — OpenShield contains after detection, it does not prevent inline (D49);
> and durable/at-scale operation is not yet hardened. It is still pre-alpha: no packaged release,
> not production-hardened, and everything below about what it does *not* claim still holds.

## The idea

Everything moves through one fixed pipeline:

```
Event → Classification → Policy → Decision → Enforcement → Audit → Investigation → Analytics
```

New capabilities arrive as new **Event producers**, **Classifiers**, **Policies** and
**Enforcers**.

The precise claim — narrowed after testing it on paper ([T-004](docs/design-t004-peer-ueba.md)) —
is that capabilities of the *same shape* as existing ones require no core changes. A capability
introducing a new *shape* of data flow requires a core addition. The pipeline's value is that
such additions are rare, small, and identifiable in advance rather than discovered mid-build.

The stronger claim — "no capability ever requires a core change" — is false, and we know exactly
which capability falsifies it: peer-baseline UEBA needs a risk score to reach Policy, which is a
feedback edge a linear pipeline cannot express.

Detection and enforcement are kept completely separate, following CrowdSec's model: an Enforcer
receives only a `Decision`. It never learns which classifier matched, which regex fired, or how
confidence was computed. That separation is what lets enforcement points be written
independently.

## What it does and does not claim

This project takes honesty about its limits seriously, because its predecessors did not.

**It can:** give local-first visibility into data movement on Linux endpoints · create friction
and an audit trail for careless insiders · maintain a tamper-*evident* log with forward
integrity between anchors.

**It cannot:** prevent a determined person from exfiltrating data · stop anyone who has root on
their own machine · offer a tamper-*proof* log (impossible in a single self-hosted trust
domain) · reliably catch a motivated adversary who encrypts, screenshots or retypes.

**The network gateway is content-inspection egress DLP, not a NIPS or a Zero-Trust enforcement
point.** It inspects only HTTP(S) that clients are configured to proxy through it, and it
authenticates no user or device identity — the network subject is a hashed source address, not
an identity. Identity-aware authorization and broader-protocol/transparent coverage are on the
roadmap, not built.

The design centre is the **careless insider**, and most real data-loss events are careless.
Read [`docs/threat-model.md`](docs/threat-model.md) before drawing conclusions about efficacy.

## Design commitments

- **Local-first.** Classification, policy evaluation and enforcement happen on the endpoint.
  The server coordinates; it does not continuously control.
- **Privacy-first, honestly.** Only *type + confidence + count* leaves the endpoint. Hashing is
  **not** used as a privacy control for low-entropy identifiers (SSN, CPF, card numbers) —
  those keyspaces are brute-forceable and salting doesn't fix it. Embeddings and fuzzy
  fingerprints are treated as content-equivalent, never as de-identification.
- **Safe by construction.** The privileged process never parses attacker-controlled bytes;
  all content parsing runs in an unprivileged sandboxed worker.
- **Closed enforcement surface.** The action set is fixed and typed, so a compromised control
  plane cannot express "upload this file somewhere".
- **Privacy law is architecture.** Retention limits, purpose tagging, exclusion lists,
  pseudonymisation and view-auditing are Phase-1 features, not later additions.

## Where things are

| Path | What |
|---|---|
| [`docs/decisions.md`](docs/decisions.md) | **Canonical decision register (D1-D59).** Single source of truth for *why*. |
| [`CHANGELOG.md`](CHANGELOG.md) | What was built, in order — the milestone arc. |
| [`docs/threat-model.md`](docs/threat-model.md) | What this stops, and what defeats it. |
| [`docs/brief.md`](docs/brief.md) | Why this exists, what "done" means, the stack. |
| [`docs/plan-phase1.md`](docs/plan-phase1.md) | Roadmap — 29 tickets, ~122 agent-hours. Source of truth for *what* and *when*. |
| [`docs/research-scouting-r1.md`](docs/research-scouting-r1.md) | Round-1 research: kernel hooks, policy engines, prior art. |
| [`docs/research-review-r1.md`](docs/research-review-r1.md) | Four adversarial reviews: architecture, cryptography, red team, law. |
| `openspec/` | Active work. Source of truth for *how* and *now*. |

Research reports are **append-only historical records** — they capture what was known at the
time and are never rewritten. Living documents reference decisions by number instead of
restating them.

## Roadmap

Phase 1 shipped **observe-and-audit** on Linux: events are classified, policies produce
Decisions, and Decisions are recorded in a forward-secure ledger. Enforcement now exists as a
post-decision step — quarantine, USB, and encrypt-local (with public-key escrow) — but is
**observe-only by default**: an enforcer must be explicitly registered, per action. Nothing is
enforced inline (the triggering access already happened); enforcement CONTAINS after detection, it
does not prevent. Inline blocking stays deferred until the classifier's real false-positive rate is
known from live data — a DLP tool that blocks on a noisy classifier is hostile to its own users.

Also built beyond the observe path: a fleet control plane (per-agent Ed25519 identity, single-use
enrollment, signed telemetry with replay/gap detection, dead-man's-switch), server-side peer-baseline
UEBA, mutual-TLS transport with certificate role authorization, and an authenticated operator
view-audit. Later phases add Cloud, Email, Developer and Collaboration security, identity-aware
policies, AI security, discovery and lineage — each as new connectors and enforcers.

## Licence

[Apache-2.0](LICENSE). Permissive, with an explicit patent grant. There is no field-of-use
restriction — see [`ETHICS.md`](ETHICS.md) for why that was a conscious choice and what we ask
of you anyway.


## Running the dev stack

```
podman-compose up -d
```

Brings up Postgres + NATS + the control plane from a clean checkout — the server
migrates on boot, no manual steps. This is a **dev stack**: default credentials
and plaintext transport, not production. Mutual TLS on the agent-facing channels
is opt-in (off by default) via the `OPENSHIELD_TLS_*` env vars; `deploy/mtls-e2e.sh`
exercises it end to end with a throwaway CA. Use `podman-compose` (native), not
`podman compose` (which needs a Docker socket rootless Podman lacks). The agent
runs on an endpoint (it needs host access), not in this stack.
