# Tasks — Zero-Trust identity context contract (D85)

## 1. Context fields (core)

- [x] 1.1 `internal/core`: add `Identity string`, `Role string`, `DevicePosture DevicePosture` to `Context`; `type DevicePosture struct { HasPosture, Compliant, DiskEncrypted, AgentPresent bool; OSPatchTier PatchTier }`; `type PatchTier int` with PatchUnknown/PatchCurrent/PatchStale/PatchEndOfLife. Closed typed set (D28); HasPosture makes absence explicit.

## 2. Policy projection

- [x] 2.1 `internal/policy/mapping.go` buildInput: expose `input.context.{identity, role, device_posture:{has_posture, compliant, disk_encrypted, agent_present, os_patch_tier}}`, extending the existing risk block — boundary-safe closed projection.

## 3. Proof (guards, each mutation-tested)

- [x] 3.1 **Test** (fitness, peer_test.go shape): an identity-aware rego over the UNCHANGED `core.Dispatcher` with a `ResolveContext` hook — a compliant finance device → ALLOW; NO posture (has_posture=false) → BLOCK (tamper-lockout); present-but-non-compliant → BLOCK. Proves identity-aware authz + fail-closed-on-absent-posture through the unchanged dispatcher/State/Stage.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D85: the ZT identity context contract — typed Identity/Role/DevicePosture with HasPosture (D28 absent-explicit), absent posture fails closed for access (tamper-lockout), decided through the unchanged dispatcher via the D53 seam; the producer/access-proxy/catalog/risk-loop are later Phase-A increments.
- [x] 4.2 `openspec validate zt-identity-context --strict`; `make all` + `-race`; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| device_posture not exposed to policy | `TestIdentityAwareAuthorization` |
| has_posture masked as present (absent→present) | `TestIdentityAwareAuthorization` (wrong reason on the no-posture case) |

THE VERDICT (D85): core.Context carries typed Identity/Role/DevicePosture with HasPosture (D28
absent-explicit); an identity-aware policy decides authorization and the device-posture tamper-lockout
(absent posture fails CLOSED for access) through the unchanged dispatcher via the D53 seam. Contract
settled + proven before the producer. NOT in scope: the identity producer (§5.2), access-proxy mode
(§5.1), service catalog (§5.4), risk-publish loop (§5.5).
