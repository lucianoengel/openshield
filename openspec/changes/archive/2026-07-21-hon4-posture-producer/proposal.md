## Why

HON-4 (P1). The posture channel (`PostureStore`/`PostureSubscriber`, D92/SEC-1) had a store
and a signed subscriber but NO PUBLISHER — nothing ever emitted a `PostureUpdate`, so the D85
device-posture tamper-lockout could never see real data (a posture-gated policy denied
everyone), and SEC-1's posture verification had only its REJECT path tested. This adds the
endpoint producer that reports device posture, agent-key-signed.

## What Changes

- `internal/posture`: `Detect` (honest best-effort device state), `Build`/`Sign` (a signed
  PostureUpdate the gateway verifies, SEC-1), `Publish` (to the posture subject). The subject
  is the reporting agent's own pseudonym (bound to the signer).
- `cmd/openshield-fleet-agent`: opt-in posture reporting when `OPENSHIELD_POSTURE_SIGNING_KEY`
  is set — publishes detected posture on each tick.
- `openshield-provision posture-keygen` emits the keypair.

## Capabilities

### Added Capabilities
- `device-posture`: an endpoint producer reports signed device posture.

## Impact

- New `internal/posture`; fleet-agent wiring; provision command; `docs/decisions.md` D124.
- Proven: a posture update BUILT by the producer is ACCEPTED by the gateway's SEC-1 signed
  subscriber and applied to the store (the posture HAPPY-PATH, finally — the D85 tamper-lockout
  now has real data), while a WRONG-KEY update is rejected and does not reach the store; `Build`
  refuses an empty subject; `Detect` is HONEST (AgentPresent true, Compliant never exceeds the
  disk-encryption evidence, OSPatchTier Unknown). Guards mutation-tested (Detect-asserts-
  compliance-without-evidence; empty-subject; sign-over-wrong-bytes).
- NOT in scope (stated): per-subject key binding at the GATEWAY (SEC-1 verifies against ONE
  trusted posture key; mapping subject→per-agent key so agent A cannot sign agent B's posture
  is a hardening follow-up — for now a shared posture-signing authority signs, and the subject
  binds the report to the reporting agent); TPM/measured-boot attestation (ZT-1 — self-report
  is only as trustworthy as the reporter); richer detection (disk encryption is a best-effort
  /proc/mounts check; patch currency needs an OS feed). Subject-space unification (device vs
  user identity) is a deployment concern.
