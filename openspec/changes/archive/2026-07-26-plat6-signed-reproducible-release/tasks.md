## 1. Manifest
- [x] 1.1 `internal/release`: `Manifest{Version, Commit, GoVersion, Entries[]{Name, Platform, Size, SHA256}}`,
      canonical serialization, `Build(dir)`, `Sign`, `Verify(dir, manifest, sig, pub)`.
- [x] 1.2 Verify reports: digest mismatch (names the artifact), bad signature, missing entry, and a file
      present but UNNAMED.

## 2. Release procedure
- [x] 2.1 `scripts/release.sh`: reproducible flags, per-platform builds, manifest + signature into dist/.
- [x] 2.2 `make release` / `make verify-release`.

## 3. Tests
- [x] 3.1 Reproducibility: build one command twice with the release flags, digests identical.
- [x] 3.2 A valid release verifies; a modified ARTIFACT fails naming it (**mutation:** compare sizes only
      → FAILS); a modified MANIFEST fails signature; an UNNAMED extra file is reported (**mutation:**
      iterate manifest entries only → FAILS).
- [x] 3.3 No private key material appears in the release output.

## 4. Gate and land
- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 4.2 Record D264; roadmap PLAT-6 → increment 1 done, goreleaser/Helm/Sigstore named as remaining.
- [x] 4.3 Sync specs and archive.
