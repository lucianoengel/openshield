# Tasks — device-posture producer (D92)

## 1. Proto + subject

- [x] 1.1 `PostureUpdate` proto + `natsx.SubjectPosture`. Regenerated.

## 2. Posture store + subscribe

- [x] 2.1 `gateway.PostureStore` (per-subject core.DevicePosture; Set sets HasPosture=true; Get has=false when absent); `ApplyPostureUpdate` (decode + Set; malformed/empty error); `SubscribePosture`.

## 3. Access enrichment

- [x] 3.1 `AccessProxy.SetPostureStore` — enrich idCtx.DevicePosture from the store; absent subject keeps HasPosture=false (tamper-lockout, D85).

## 4. Proof (guards, each mutation-tested)

- [x] 4.1 **Test** (real TLS + client certs): a policy gating on `device_posture.has_posture` for role finance; with NO posture published → the finance client is DENIED 403 (the tamper-lockout); after `PostureStore.Set(subject, {Compliant:true})` → the SAME client is ALLOWED.
- [x] 4.2 **Test**: `ApplyPostureUpdate` decodes a PostureUpdate into the store (Get has=true, compliant); a malformed/empty-subject payload errors.

## 5. Docs, ship

- [x] 5.1 `docs/decisions.md` D92: the device-posture producer — the gateway reads published posture into a PostureStore, the access proxy enriches DevicePosture, and an unattested device fails closed (the D85 tamper-lockout demonstrated); mirrors the risk channel D91 but fails in the opposite direction; the endpoint report/attestation side is a follow-up.
- [x] 5.2 `openspec validate gateway-device-posture --strict`; `make all` + `-race`; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| `PostureStore.Set` drops `HasPosture=true` (stored posture reads as absent) | tamper-lockout test — the compliant device is then denied (posture reads absent) |
| access enrichment forces `HasPosture=true` on an absent subject (defeats the lockout) | tamper-lockout test — the no-posture device is then wrongly allowed |
| `ApplyPostureUpdate` empty-subject guard removed | ApplyPostureUpdate test — an empty-subject payload no longer errors |
