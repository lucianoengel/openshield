# Tasks — HON-4 signed posture producer (D124)

## 1. Producer

- [x] 1.1 internal/posture: Detect (honest best-effort), Build/Sign (signed PostureUpdate), Publish; fleet-agent opt-in loop; provision posture-keygen.

## 2. Proof (guards mutation-tested)

- [x] 2.1 **Test**: the producer's signed posture round-trips through the gateway SEC-1 subscriber (applied); wrong-key rejected; empty subject refused; Detect is honest.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D124.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| Detect asserts compliance without evidence | the honesty test (Compliant exceeds DiskEncrypted) |
| empty-subject guard removed | Build accepts an empty subject |
| Sign over wrong bytes | the subscriber rejects the round-trip (bad signature) |
