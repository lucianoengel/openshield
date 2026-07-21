## Context

`core.Context` (D28) is a closed typed enrichment set resolved via the dispatcher's
`ResolveContext` hook (D53) and projected to policy by `buildInput` — today only
`risk_score`/`has_risk_score` cross (peer-UEBA, D53/D54). Zero-Trust authorization
needs the same seam to carry identity, role, and device posture. The identity
PRODUCER (§5.2) is the real auth-layer work; this settles the contract it targets.

## Goals / Non-Goals

**Goals:** typed identity/role/device-posture on `Context`; a boundary-safe policy
projection; prove identity-aware authz + the tamper-lockout decide through the
unchanged dispatcher.

**Non-Goals:** the identity producer, access-proxy mode, service catalog, risk-publish
loop — later increments.

## Decisions

**Typed fields, never a map (D28).** Identity/Role are strings; DevicePosture is a
closed struct with a `PatchTier` enum. A `map[string]any` context would be an open
key surface a compromised control plane could exploit (D14's threat by another door)
— so each field is a deliberate schema edit, reviewed like an action.

**`HasPosture` makes absence explicit, and absence fails CLOSED for access.** The
D28 rule: absent enrichment must be visible, never defaulted. For RISK, absence
means "analytics down" and policy should not fail-open to "safe". For POSTURE in a ZT
ACCESS decision, absence means "untrusted/unattested device" and policy should fail
CLOSED — deny. Both are the same principle (expose the absence via `Has*`); the
policy chooses the safe direction per context. This is the tamper-lockout we want: a
killed or tampered endpoint reports no posture, `has_posture` is false, and the ZT
policy denies access at the gateway — the endpoint the user controls cannot grant
itself access by disabling its own agent.

**Contract-first, D69-style.** Prove the pipeline can REPRESENT and DECIDE on identity
before building the producer, so the producer, access-proxy mode, and catalog are
de-risked against a settled contract. The fitness test is the proof (peer_test.go's
D26 shape): a real rego policy over a real dispatcher with a ResolveContext hook.

## Risks / Trade-offs

- **The Context now carries identity — sensitive.** It is pseudonymous (D23) and
  boundary-safe-projected (only the closed field set reaches policy, not the whole
  Context). The mapping to a real identity stays behind an audited lookup (D23/D47).
- **Fields precede their producer.** Until §5.2 fills them, `Context.Identity`/posture
  are empty and `has_posture` is false — so a ZT policy written against them denies by
  default, which is the correct fail-closed posture, not a gap.
