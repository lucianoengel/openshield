## Why

D85 established that absent device posture fails CLOSED (the tamper-lockout), but the
gateway had no posture SOURCE — posture was always absent, so a posture-requiring
policy denied everyone. This adds the device-posture producer (mirroring the risk
channel D91): the endpoint reports device state, the gateway populates a PostureStore,
and the access policy can require an attested, compliant device. This finally
demonstrates the tamper-lockout with a real device signal.

## What Changes

- `PostureUpdate` proto (subject, compliant, disk_encrypted, agent_present,
  os_patch_tier) + `natsx.SubjectPosture`.
- `gateway.PostureStore` (per-subject `core.DevicePosture`), `ApplyPostureUpdate`
  (decode + Set; malformed/empty rejected), `SubscribePosture`.
- `AccessProxy.SetPostureStore` — enriches the identity Context's `DevicePosture` from
  published posture; a subject with NO published posture keeps `HasPosture=false` and a
  posture-requiring policy denies it (the D85 tamper-lockout).

## Capabilities

### Modified Capabilities
- `network-gateway`: the access proxy enriches decisions with published device posture;
  an unattested device fails closed.

## Impact

- New `PostureUpdate` proto, `natsx.SubjectPosture`, `gateway.PostureStore`/Apply/
  Subscribe, AccessProxy enrichment; `docs/decisions.md` D92.
- Proven with real TLS + client certs: a compliant-posture device is allowed, and a
  device with NO published posture is DENIED (the tamper-lockout demonstrated); Apply
  round-trips a PostureUpdate.
- NOT in scope (stated): the endpoint agent's posture-REPORT side (the agent computes +
  publishes its device state — a follow-up; the gateway consumption is here); per-message
  posture signing (mTLS transport D55 for now); OIDC. Respects D85 (posture fails closed),
  D92 mirrors D91, D23 (pseudonymous subject).
