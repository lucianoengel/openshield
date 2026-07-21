## Why

D85 settled the identity context contract (`core.Context` carries typed
Identity/Role/DevicePosture). This builds the PRODUCER that puts a *real verified*
subject there — authenticating a client by certificate and resolving a pseudonymous
identity + role — replacing the `sha256(src-IP)` non-identity that made "Zero Trust"
an overclaim (D84). Client-cert only (reuses the D60 CA and the D58 cert-role
pattern); OIDC/bearer is a noted follow-up.

## What Changes

- `provision.RoleClient = "client"` + `IssueClientCert(caCertPEM, caKeyPEM, identity,
  group)` — a DISTINCT issuance path beside `IssueCert` (unchanged, agent/operator
  only): an Ed25519 leaf with CN = identity, OU = [RoleClient] (so a client cert can
  never be mistaken for an agent/operator cert at the D58 gate), O = [group],
  clientAuth only.
- `internal/gateway/identity.FromClientCert(leaf)` — verify the leaf carries the
  RoleClient OU (reject anything else), extract identity from CN and group from O[0];
  PSEUDONYMISE the identity one-way (D23 — `Subject = "sub_"+hash(CN)`, so the raw
  identity never enters the pipeline; reverse mapping is a deployer concern behind an
  audited lookup) and keep the group as `Role`. Returns `Identity{Subject, Role}`.
- `Identity.Context()` — a `core.Context` with `Identity`/`Role` set and
  `DevicePosture.HasPosture=false` (posture is a separate producer; absent posture
  correctly fails closed, D85). This is the resolver the access-proxy mode (§5.1) will
  call per connection.

## Capabilities

### Modified Capabilities
- `provisioning`: client-role cert issuance, distinct from agent/operator.
- `network-gateway`: a verified client identity resolves into the ZT context,
  replacing the hashed source IP.

## Impact

- New `provision.IssueClientCert` + `RoleClient`, new `internal/gateway/identity`;
  `docs/decisions.md` D86. `IssueCert` and the existing roles are unchanged.
- Proven with real certs: a client cert → a PSEUDONYMOUS subject (not the raw
  identity) + role; an agent/operator cert is rejected; the Context has Identity/Role
  and HasPosture false (fail-closed until posture runs).
- NOT in scope (stated): OIDC/bearer (A.2b); the access-proxy mode that calls this
  (§5.1/A.3); the device-posture producer; the service catalog (§5.4); the
  risk-publish loop (§5.5). Respects D60, D58, D23, D85, D14.
