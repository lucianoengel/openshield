#!/usr/bin/env bash
# PLAT-6: build a REPRODUCIBLE, SIGNED artifact set.
#
# Reproducibility is the property the signature depends on: without it a signature attests only that the
# signer had *a* binary, and nobody but the signer can establish that an artifact corresponds to the
# source. Hence -trimpath (no build-machine paths), CGO_ENABLED=0 (no host toolchain variance) and
# -buildvcs=false (VCS state is recorded in the manifest, not baked into binaries where a dirty tree
# changes the output).
#
# The private key never enters the repository or the output: OPENSHIELD_RELEASE_KEY names a file, and only
# the public key ships.
set -euo pipefail

DIST=${DIST:-dist}
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
COMMIT=${COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}

# The linker target for the release version. It was `main.version` for as long as this script existed and
# NO cmd/*/main.go ever declared that variable — the Go linker silently ignores an -X target that does not
# exist, so every shipped binary carried no version and the flag was decorative. One symbol in one
# package, because twelve per-command variables is twelve places to forget; internal/doccheck asserts that
# the path below still names a variable that exists, so a rename fails a test instead of quietly
# un-stamping the fleet.
VERSION_SYMBOL="github.com/lucianoengel/openshield/internal/buildinfo.Version"

rm -rf "$DIST"; mkdir -p "$DIST"

# Linux-only commands are built for Linux ONLY; the manifest records each artifact's platform rather than
# the release implying it runs everywhere.
LINUX_ONLY="openshield-server openshield-gateway openshield-worker openshield-print-filter"
PORTABLE="openshield-agent openshieldctl openshield-anchor openshield-engine openshield-provision openshield-fleet-agent openshield-fim-baseline openshield-dlp-index"

build() { # $1=cmd $2=goos $3=goarch
  local out="$DIST/$1_$2_$3"
  CGO_ENABLED=0 GOOS="$2" GOARCH="$3" go build \
    -trimpath -buildvcs=false \
    -ldflags "-s -w -X $VERSION_SYMBOL=$VERSION" \
    -o "$out" "./cmd/$1"
}

for c in $LINUX_ONLY; do build "$c" linux amd64; build "$c" linux arm64; done
for c in $PORTABLE; do
  build "$c" linux amd64; build "$c" linux arm64
  build "$c" darwin arm64; build "$c" windows amd64
done

go run ./cmd/openshieldctl release-manifest \
  --dir "$DIST" --version "$VERSION" --commit "$COMMIT" \
  --key "${OPENSHIELD_RELEASE_KEY:?set OPENSHIELD_RELEASE_KEY to the ed25519 private key file}"

# Native packages, built FROM the signed set (PLAT-6 inc 2).
#
# They land NEXT TO the release directory, never inside it: the manifest signature covers the SET, so an
# unlisted file in $DIST makes verify-release fail with "present but not in the manifest" — the wording of
# a tamper detection, produced by the packaging step (D447).
#
# The key used here is the one this script just derived from the signing key, so this is an INTEGRITY
# self-check — it confirms the signing step produced a coherent set. It establishes nothing about
# authenticity, which is a property of a key an operator obtained out of band, and package-deb's own
# output says so.
PKGDIR=${PKGDIR:-$DIST-packages}
rm -rf "$PKGDIR"; mkdir -p "$PKGDIR"
for arch in amd64 arm64; do
  go run ./cmd/openshieldctl package-deb \
    --dir "$DIST" --key "$DIST/release-key.pub" --version "${VERSION#v}" --arch "$arch" \
    --units deploy/systemd --out "$PKGDIR/openshield_${VERSION#v}_${arch}.deb"
done

echo "release: $DIST ($VERSION) — verify with: make verify-release"
echo "packages: $PKGDIR"
