## Why

Audit finding #2b, verified: external anchoring (T-019/D38) — the mechanism that
bounds truncation/rewrite by a determined adversary — is implemented and
unit-tested (`AnchorHead`) but has ZERO callers. No CLI, no cron, no binary ever
invokes it. So every real deployment is permanently `Completeness: UNVERIFIED`,
and the one control that catches an adversary who bypasses the D63 append-only
trigger (a table owner can disable it) never runs. Anchoring exists on paper only.

## What Changes

- **Witness-key persistence (core).** `core.NewWitness` only GENERATES a keypair;
  a witness that regenerates every run anchors under a key nobody can verify
  against. Add `WitnessFromKey(priv)` and expose the private key bytes, so a
  witness key can be saved once and reloaded.
- **A runnable witness tool (`cmd/openshield-anchor`).** It loads the witness key
  from a file, opens the ledger SIGNER-LESS (`OpenForVerify` — the witness holds
  ONLY the witness key, never the ledger signer; it attests, it cannot append),
  calls `AnchorHead` to witness and store the current head, and logs the anchored
  sequence. One-shot by default (for a systemd timer / cron), `--interval` for a
  loop.
- **`openshield-provision witness-keygen`** generates the witness keypair — the
  private key for the witness host, the public key for verifiers — mirroring
  `escrow-keygen`.
- **`openshieldctl verify --witness <pub>`** sets the witness public key so an
  auditor can VERIFY completeness (a read-only operation — openshieldctl stays
  signer-less). Without it, verification reports the honest `UNVERIFIED` degraded
  mode as today.
- **Scheduling + docs.** A systemd `openshield-anchor.service` + `.timer` and
  `install.sh` wiring; docs on witness custody.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `audit-ledger`: external anchoring is now RUNNABLE and schedulable — a witness
  tool witnesses the head on a timer and an auditor can verify completeness
  against the witness public key, moving deployments off permanent `UNVERIFIED`.
- `provisioning`: adds witness-keypair generation.

## Impact

- New: `core.WitnessFromKey` + private-key export; `cmd/openshield-anchor`;
  `openshield-provision witness-keygen`; `openshieldctl verify --witness`;
  systemd timer + install; docs (D64).
- HONEST trust model (T-019, already in `AnchorHead`'s doc): the witness MUST be
  provisioned in a trust domain the deployer does NOT control (a second host, WORM
  storage, a transparency service) — an anchor witnessed by a key the deployer
  holds attests to little. This change makes anchoring RUNNABLE and schedulable;
  witness-key custody is the operator's responsibility and DETERMINES the
  guarantee, and the undetectable-loss window is the interval between anchors
  (choosing the schedule chooses the window). Respects D30/D38.
