## Why

There is no way to ship this. `deploy/` already carries systemd units and an install script, so the
*deploy* half exists — what does not exist is anything an operator can verify. There are no tagged
artifacts, no digests, no signatures, and no way for someone who downloads a binary to establish that it
is the one this repository produced.

For a security product that is not a packaging nicety. The thing being installed runs as root on every
endpoint, and "trust me, this tarball is fine" is the supply-chain posture the product exists to argue
against.

## What Changes

- **`make release`** builds every command for the supported platforms with **reproducible** flags
  (`-trimpath`, `CGO_ENABLED=0`, pinned build metadata, no embedded paths or VCS state), emits a
  `SHA256SUMS` manifest, and signs that manifest with a **detached ed25519 signature** — the same
  primitive the platform already uses for feeds, intents and risk, rather than a new toolchain.
- **`make verify-release`** re-checks every digest against the manifest and the manifest against the
  public key, so verification is a command an operator runs, not a paragraph in a README.
- **Reproducibility is asserted by test**: build the same commit twice and the digests must match. A build
  that is not reproducible cannot be independently verified, so this is the property the signature is
  worth something *because of*.
- **A tampered artifact fails verification** — asserted, with the failure naming which file.
- **The signing key never enters the repository or the release output.** It is a file path supplied at
  release time; only the public key ships.

## Capabilities

### Modified Capabilities
- `packaging`: adds reproducible builds, a signed digest manifest, and an operator-runnable verification
  path.

## Impact

- **New code**: `internal/release` (manifest build/verify), `scripts/release.sh`, Makefile targets.
- **No migration, no proto change, no new dependency** — ed25519 and SHA-256 are stdlib.
- **Honest scope**: **no goreleaser and no Helm chart** in this increment. Both are real work with their
  own decisions (goreleaser adds a toolchain and a config surface; Helm implies a Kubernetes deployment
  model this project has not committed to), and neither is needed for the property that matters, which is
  *verifiable* artifacts. No transparency log or Sigstore/cosign — those need network identity and a
  keyless trust root, which is a different trust decision, not a bigger version of this one. No SBOM. No
  OS packages (.deb/.rpm) or notarized macOS builds. No release automation in CI — `make release` is
  runnable locally and by CI, but wiring the tag trigger is separate. Cross-compilation covers the
  platforms already in `make cross-compile`; the Linux-only commands are built for Linux only, and the
  manifest says which platforms each artifact covers rather than implying more.
