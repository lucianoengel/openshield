## Why

The device-posture chain is **inert in production**. The fleet-agent publishes posture keyed by
the raw `agentID`, but the access proxy looks it up under `pseudonym(CN)` derived from the device
certificate. `rawAgentID ≠ "sub_"+hex(sha256("zt-client-subject:"+CN))` — the keys never match, so
the verified, stored posture is never found, every real compliant device reads `HasPosture=false`,
and any posture-gated policy denies it. ZT-3's headline path ("finance user on a compliant device →
200") is unreachable. The feature's tests pass only because they seed `Set(pseudonym(CN))` and read
back the same literal — the project's recurring *"verifies against its own assumptions"* pattern
masking a HIGH-severity production bug (confirmed by three independent audit agents). SEC-12's
signature binding is correct; the *identity wiring around it* is broken. This is the top of the
Round-33 queue and blocks ZT-1 (attestation binds to whatever identity is chosen) and XDR-1 (the
same canonical-identity work).

## What Changes

- Export **one** shared device-pseudonym derivation (today the unexported
  `identity.pseudonym`) and make it the single source of the canonical subject key across the
  posture publisher, the posture roster/verifier, and the access proxy.
- The fleet-agent publishes device posture under the **canonical pseudonym of its enrolled agent
  identity**, not the raw `agentID`/`OPENSHIELD_SUBJECT`. **BREAKING** for any deployment that
  populated the posture roster with raw agent IDs — the roster is now keyed by the canonical
  pseudonym.
- The SEC-12 posture roster/`keyFor` resolver (`LoadPostureRoster`) is re-keyed to the canonical
  pseudonym, so signature verification still binds each update's subject to the reporting agent's
  enrolled key.
- Provisioning documents/enforces that a **RoleClient device certificate carries `CN = the enrolled
  agent identity`**, so the proxy's `pseudonym(CN)` equals the publisher's `pseudonym(agentID)`.
- D23 pseudonymization is **preserved** — the one-way derivation is shared, never removed; no raw
  identity enters the pipeline.
- Verification is an end-to-end test driving the **real** `posture.Publish` → gateway store →
  proxy lookup, plus a mutation (revert the publisher to the raw subject) that must flip the test
  to FAIL. No test may seed the store with the value it then asserts.

## Capabilities

### New Capabilities
<!-- none — this is a cross-cutting correctness fix over existing capabilities -->

### Modified Capabilities
- `device-posture`: the subject under which posture is published, stored, verified, and resolved is
  the canonical one-way pseudonym of the enrolled agent identity, produced by a single shared
  derivation — not the raw agent ID.
- `network-gateway`: the access proxy resolves device posture through the same shared canonical
  device-pseudonym derivation (no independent/divergent derivation permitted).
- `provisioning`: a RoleClient device certificate's `CN` is the enrolled agent identity, so the
  proxy-side `pseudonym(CN)` matches the agent-side `pseudonym(agentID)`.

## Impact

- **Code:** `internal/gateway/identity` (export/relocate the shared derivation),
  `cmd/openshield-fleet-agent/main.go` + `internal/posture` (publish under the canonical pseudonym),
  `internal/gateway/posture.go` (`LoadPostureRoster`/`keyFor` re-keyed), `internal/provision`
  (cert-CN convention + doc), and the affected tests (posture, ZT-3 dual-credential, gateway access).
- **No core/proto change** — the frozen `core.Dispatcher`/`State`/`Stage`/`Enforcer`/ledger and the
  D10/D29 content boundary are untouched; this is producer + gateway + provisioning wiring.
- **Deployment:** operators who maintain a posture roster file must re-key entries to the canonical
  pseudonym; device certs must be issued with `CN = agent identity`. Documented as a migration note.
- **Unblocks:** ZT-3 becomes reachable in production; ZT-1 (attestation) and XDR-1 (entity identity)
  can bind to a stable canonical identity.
