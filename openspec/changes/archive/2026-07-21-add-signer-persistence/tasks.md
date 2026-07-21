## 1. Export/Load

- [x] 1.1 `SignerState{Epoch, Priv, Chain}`; `Signer.Export()` gob-encodes it (current priv only)
- [x] 1.2 `core.LoadSigner(blob)`: decode + validate (non-empty chain, priv size, epoch in range,
      priv's public half == chain[epoch].PublicKey); reconstruct
- [x] 1.3 **Test**: export→load round-trips; a signer with only the current key; a mismatched
      priv/chain fails to load. `TestSignerExportLoad`

## 2. File helper

- [x] 2.1 `SaveSignerFile(path, s)` (atomic, 0600) + `LoadSignerFile(path)`
- [x] 2.2 **Test**: save then load yields a working signer; the file is mode 0600. `TestSignerFile`

## 3. Write-resume (real Postgres)

- [x] 3.1 **Test**: append; export; NEW signer via LoadSigner; postgres.Open (resume) succeeds;
      append more; whole chain verifies continuously. `TestWriteResumeWithReloadedSigner`
- [x] 3.2 Confirm a genuinely foreign signer is still refused (existing
      `TestWriteResumeWithForeignSignerIsRefused` stays green)

## 4. Docs

- [x] 4.1 Note in `docs/decisions.md` (new D-number): signer current-state export/reload for
      write-resume; only the current epoch; 0600 at rest, host-root defeats it, encryption-at-rest a
      follow-up
- [x] 4.2 Validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| priv/chain match check removed | `TestPrivChainMismatchRejected` (crafts a valid-checksum but mismatched blob) |
| (corruption) any byte flipped | `TestSignerExportLoad` — SHA-256 integrity prefix |

Export→load round-trips and the reloaded signer produces byte-identical
signatures (`TestSignerExportLoad`); the file is written 0600 (`TestSignerFile`).
Write-resume works against real Postgres: append → export → reload a FRESH signer
→ `postgres.Open` resumes (anchor matches) → append more → the whole 6-entry
chain verifies continuously (`TestWriteResumeWithReloadedSigner`), while a
genuinely foreign signer is still refused
(`TestWriteResumeWithForeignSignerIsRefused`). Docs: D46.
