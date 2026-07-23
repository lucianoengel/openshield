## 1. Sign / verify (`internal/fim/signed.go`)

- [x] 1.1 `fimSigDomain = "openshield-fim-baseline\x1f"`; `SignManifest(m *Manifest, priv ed25519.PrivateKey) ([]byte, error)` — marshal the manifest to JSON, sign `domain + json`, return a `{manifest_bytes, signature}` JSON envelope (the manifest bytes stored VERBATIM so verify re-checks the same bytes). Reject a bad key / empty manifest.
- [x] 1.2 `VerifyManifest(signed []byte, trustedPub ed25519.PublicKey) (*Manifest, error)` — parse the envelope, verify `ed25519.Verify(pub, domain+manifestBytes, sig)`, then unmarshal the (now-trusted) manifest bytes. Fail-closed: malformed envelope, empty/invalid sig, wrong key, wrong-size key → error + nil.
- [x] 1.3 `LoadSignedManifest(path, trustedPub) (*Manifest, error)` — read the file and `VerifyManifest`.

## 2. Signing tool (`cmd/openshield-fim-baseline`)

- [x] 2.1 `keygen --out-key k --out-pub p` — a raw Ed25519 keypair (mirror openshield-dlp-index keygen).
- [x] 2.2 `build --paths <csv> --key <priv> --out <signed>` — `fim.BuildBaseline(paths)` → `SignManifest` → write the signed envelope. `--max-hash-bytes` optional.

## 3. Engine verification (`cmd/openshield-engine/main.go`)

- [x] 3.1 When `OPENSHIELD_FIM_BASELINE_PUBKEY` (a raw 32-byte Ed25519 pub file) is set: load the baseline via `fim.LoadSignedManifest` (fatal on a missing/unsigned/invalid baseline; DISABLE first-run auto-capture — the node must not self-sign). When unset: the legacy `fim.LoadManifest` + auto-capture (D223) with a loud "unsigned baseline is tamper-vulnerable — set OPENSHIELD_FIM_BASELINE_PUBKEY" warn.

## 4. Tests (`internal/fim`)

- [x] 4.1 `TestSignVerifyRoundTrip`: `SignManifest` then `VerifyManifest` with the matching pub → the same hashes; a scan against the verified manifest behaves identically.
- [x] 4.2 `TestVerifyRejectsTamper`: alter a byte of the signed envelope's manifest region → verify FAILs, nil manifest.
- [x] 4.3 `TestVerifyRejectsWrongKey`: verify with a different pub → FAILs.
- [x] 4.4 `TestVerifyRejectsUnsigned/Malformed`: a plain (unsigned) manifest, an empty/garbage envelope → FAIL, nil.

## 5. Mutation verification

- [x] 5.1 Mutation — `VerifyManifest` skips the `ed25519.Verify` check (returns the manifest unconditionally): `TestVerifyRejectsTamper` + `TestVerifyRejectsWrongKey` FAIL. Revert.
- [x] 5.2 Mutation — the signature omits the domain tag (sign raw json): a cross-domain check (a signature over the raw bytes should NOT verify with the domain-tagged verifier) — assert `SignManifest`'s output does not verify if the domain is stripped. (Covered by the round-trip using the domain on both sides; add an explicit assertion that a raw-signed blob fails.) Revert.

## 6. Gate & land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; cross-compile clean; the new tool builds.
- [x] 6.2 decisions.md D-entry; sync the delta into `openspec/specs/file-integrity-monitoring/spec.md`; doccheck.
- [x] 6.3 Update the roadmap: FIM signed baseline (increment 3) DONE — FIM is now tamper-evident end to end. Archive; commit; `git pull --rebase`; push.
