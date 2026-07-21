# Tasks — operational anchoring

## 1. Witness persistence (core)

- [x] 1.1 `core.WitnessFromKey(priv ed25519.PrivateKey) (*Witness, error)` (validate length) and `(w *Witness) PrivateKey() ed25519.PrivateKey`.
- [x] 1.2 **Test**: a witness reconstructed from a saved private key produces anchors that `VerifyAnchor` accepts under the corresponding public key.

## 2. The witness tool

- [x] 2.1 `cmd/openshield-anchor`: load the witness key (`OPENSHIELD_WITNESS_KEY` / `--witness`), `OpenForVerify(dsn)`, `AnchorHead`, log the anchored sequence. One-shot; `--interval D` optional loop. Prints the witness-custody caveat.
- [x] 2.2 `openshield-provision witness-keygen --out DIR`: write `witness-priv` (host) + `witness-pub` (verifiers), raw bytes, 0600 on the private key.

## 3. Verification surface

- [x] 3.1 `openshieldctl verify --witness <pubfile>`: load the witness public key, set `Ledger.WitnessPub`, report completeness. Stays read-only.

## 4. Prove it moves completeness

- [x] 4.1 **Test (integration)**: open the ledger, append entries, anchor via a saved-key witness, set `WitnessPub`, and assert `Verify` returns `CompletenessAnchored` (not `UNVERIFIED`); the witness path uses `OpenForVerify` (no signer).
- [x] 4.2 `deploy/observe-e2e.sh`: after the ALERT lands, run the `openshield-anchor` BINARY to witness the head, then `openshieldctl verify --witness` and assert the range is anchored.

## 5. Scheduling, docs, ship

- [x] 5.1 `deploy/systemd/openshield-anchor.service` + `.timer`; `install.sh` builds/installs `openshield-anchor` + `openshield-provision`.
- [x] 5.2 `docs/decisions.md` D64: anchoring is operational (runnable tool + timer + witness keygen + read-only witness verify); witness custody (external trust domain) determines the guarantee; the loss window is the anchor interval; closes audit #2b.
- [x] 5.3 `openspec validate operational-anchoring --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| WitnessFromKey skips the key-length check | `TestWitnessFromKeyRoundTrips` |
| WitnessFromKey ignores the key (generates a new one) | `TestWitnessFromKeyRoundTrips` (pub mismatch) |
| anchoring does not move completeness | `TestAnchoringMovesCompleteness` |

External anchoring is now operational: a witness reconstructed from a SAVED key,
using the SIGNER-LESS path (OpenForVerify) the openshield-anchor tool uses,
witnesses the head and moves Completeness UNVERIFIED→Anchored; without the witness
pub the honest UNVERIFIED degraded mode remains. Proven at the BINARY level in
deploy/observe-e2e.sh (before=unverified → after=anchored via the real
openshield-anchor + openshieldctl verify --witness). Witness custody is the
guarantee (T-019); a systemd timer owns the schedule (= the loss window).
