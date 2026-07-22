## Context

Three parties derive the device's subject key independently today:

- **posture publisher** (fleet-agent → `internal/posture.Publish`): keys by
  `env("OPENSHIELD_SUBJECT", agentID)` — the **raw** agent id.
- **posture roster / verifier** (`internal/gateway/posture.go` `LoadPostureRoster` + `keyFor`):
  looks up the signing key by the update's raw subject; the store is written under that raw subject.
- **access proxy** (`internal/gateway/access.go`): resolves the device via
  `identity.FromClientCert(cert).Subject`, which is `pseudonym(CN)` from the **unexported, unshared**
  `internal/gateway/identity.pseudonym` = `"sub_"+hex(sha256("zt-client-subject:"+CN)[:12])`.

`rawAgentID ≠ sub_<hash>`, so the verified, stored posture is never found and every real compliant
device reads `HasPosture=false`. SEC-12's signature binding is correct; the identity wiring around it
is not. ADR-6 is the governing decision: canonicalize on the enrolled agent identity, export ONE
shared pseudonym derivation, and provision device certs with `CN = agent identity`.

## Goals / Non-Goals

**Goals:**
- One shared, one-way pseudonym derivation used by the publisher, the roster/verifier, and the proxy.
- The posture chain works on the **real** path: a device that publishes signed posture is recognized
  as attested by the proxy — proven end-to-end, with a mutation (raw-subject publish) that FAILs it.
- Preserve SEC-12 (subject↔key binding) and D23 (no raw identity in the pipeline; derivation shared,
  not removed) — existing user-cert pseudonyms remain byte-identical.

**Non-Goals:**
- Unifying the subject key across ALL telemetry domains (the agent's own `Event.PseudonymousId`,
  peer-UEBA, HIPS/DLP). That cross-domain entity identity is **XDR-1**; IDENT-1 fixes only the
  device-posture chain. The agent's event subject is left as-is.
- Hardware attestation (ZT-1), JWKS rotation (ZT-2b), or a ZTNA client.
- Any change to the frozen core, proto, or the D10/D29 content boundary.

## Decisions

### D-a · The shared derivation lives in a new zero-dependency package `internal/pseudonym`
`func Of(identity string) string` returning the exact current bytes
(`"sub_"+hex(sha256("zt-client-subject:"+identity)[:12])`). Imported by `internal/gateway/identity`
(its `pseudonym` becomes a thin call), `internal/posture`, `internal/gateway` (roster), and the
provisioning test.

*Alternative considered:* export `identity.Pseudonym` from `internal/gateway/identity` and import
that everywhere. **Rejected** — the posture publisher runs inside the endpoint fleet-agent, and
`internal/gateway/identity` transitively pulls in `internal/provision` (PKI/cert code); coupling the
endpoint publisher to gateway+PKI packages is the wrong dependency direction. A pure-crypto
`internal/pseudonym` (only `crypto/sha256`, `encoding/hex`) is importable from both sides with no
cycle and gives ADR-6's "ONE derivation" a single neutral home.

### D-b · The publisher keys posture by `pseudonym.Of(agentID)`, and the `OPENSHIELD_SUBJECT` override no longer applies to posture
The raw-subject path was the bug. The fleet-agent publishes device posture under
`pseudonym.Of(agentID)`. `OPENSHIELD_SUBJECT` continues to influence only the agent's own event
subject (out of scope, XDR-1) — it must not be able to mis-key posture.

### D-c · The roster stays human-writable (`<agent-identity> <base64-pubkey>`); the loader canonicalizes
`LoadPostureRoster` keys the resolver map by `pseudonym.Of(field0)` rather than the raw field, so
operators keep writing agent identities (not opaque hashes) and `keyFor(pseudonym.Of(agentID))`
resolves. This keeps SEC-12 intact: the incoming update's subject is `pseudonym.Of(agentID)` and the
roster key is derived identically.

*Alternative considered:* require the roster file to contain pre-computed pseudonyms. **Rejected** —
opaque and error-prone for operators, and it would duplicate the derivation into deploy tooling.

### D-d · Device certificates carry `CN = agent identity`; the proxy path is unchanged
`provision.NewClientCert` already sets `CN = identity`; the requirement is a provisioning
convention (issue a device's client cert with `identity = agentID`) plus documentation. The proxy
keeps computing `pseudonym(CN)` — now via `pseudonym.Of` — so `pseudonym(CN) == pseudonym.Of(agentID)`
and the published posture is found. No behavioral change to `FromClientCert` beyond routing through
the shared derivation.

### D-e · Verification drives the real path, never a seeded literal
The e2e publishes through the real `posture.Publish`, lets the gateway verify+store, then resolves a
device cert (`CN = agentID`) at the proxy and asserts posture PRESENT and the compliant device
allowed; a no-posture device denied. The mutation guard reverts the publisher to the raw agent id and
asserts the test FLIPS to FAIL. No test seeds the store with the key it later asserts.

## Risks / Trade-offs

- **Existing user-cert pseudonyms must not change** → move the derivation byte-for-byte and add a
  golden-value test pinning `pseudonym.Of` output, so a future edit to the domain string is caught.
- **BREAKING for roster files keyed by a non-identity subject** → the loader now derives the key from
  the first field as an *agent identity*; documented in the migration note. Files that already list
  agent identities need no change.
- **Stale posture stored under old raw keys after upgrade** → posture is re-published every heartbeat
  interval, so the store self-heals within one interval under the canonical key; no migration of
  stored posture is needed (it is ephemeral, not the system of record).
- **Scope creep toward full entity identity** → explicitly deferred to XDR-1; IDENT-1 touches only the
  posture subject, keeping the change reviewable and the frozen core untouched.

## Migration Plan

1. Ship `internal/pseudonym`; route `identity.pseudonym`, the publisher, and the roster loader
   through it.
2. Operators: ensure posture roster lines list the **agent identity** in field 1 (unchanged if they
   already do); issue device client certs with `CN = agent identity`. Both documented in the
   provisioning/deploy notes.
3. No data migration: agents re-publish posture under the canonical key within one heartbeat interval.
   Rollback is reverting the commit — posture returns to inert (the prior state), never worse.

## Open Questions

None — ADR-6 settles the derivation, the identity anchor, and the cert-CN convention.
