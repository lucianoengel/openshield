## Why

The Zero-Trust access phase (proposal §5) needs the pipeline to carry a verified
identity, role, and device posture into policy. Contract-first — exactly as D69
proved the network Event/verdict contract before building the proxy — this settles
that CONTEXT contract and proves the pipeline can DECIDE on it, through the UNCHANGED
dispatcher via the existing `ResolveContext`/`State.Context` seam (D28/D53), before
building the identity PRODUCER (§5.2) that fills it.

## What Changes

- `core.Context` gains three TYPED fields (D28 — a closed typed set, never a map):
  `Identity` (verified pseudonymous subject, D23), `Role` (authorization group), and
  `DevicePosture` (`{HasPosture, Compliant, DiskEncrypted, AgentPresent, OSPatchTier}`
  + a `PatchTier` enum). `HasPosture` distinguishes "not computed" from "computed and
  compliant" — like `HasRiskScore` — so absent posture is VISIBLE to policy and can
  fail CLOSED for access (the tamper-lockout: a killed endpoint reports no posture →
  the ZT policy denies).
- `policy.buildInput` exposes them under `input.context.{identity, role,
  device_posture:{...}}`, extending the existing risk block (D53) — a boundary-safe
  closed projection, never the whole Context.
- A fitness test proves an identity-aware policy decides through the unchanged
  dispatcher: compliant finance device → ALLOW; no posture → BLOCK; non-compliant →
  BLOCK.

## Capabilities

### Modified Capabilities
- `pipeline-dispatcher`: `Context` carries typed identity + role + device posture.
- `policy-evaluation`: policy decides identity-aware authorization, and absent
  posture fails closed for access.

## Impact

- Additive fields on `core.Context`, a `buildInput` projection, a fitness test;
  `docs/decisions.md` D85. ZERO change to the dispatcher, State, Stage, or Enforcer
  interfaces.
- NOT in scope (stated): the identity producer / OIDC / client-cert auth layer
  (§5.2); the reverse/access-proxy mode (§5.1); the service catalog + microsegmentation
  (§5.4); the risk-publish continuous-verification channel (§5.5) — later Phase-A
  increments on this contract. Respects D28, D53, D23, D14, D69.
