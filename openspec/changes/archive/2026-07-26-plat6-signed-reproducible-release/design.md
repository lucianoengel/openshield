## Context

`deploy/` already carries systemd units, hardening drop-ins and an install script, so the deploy path is
not the gap. The gap is that nothing produced by this repository can be verified by whoever installs it.

## Goals / Non-Goals

**Goals:** reproducible builds; a signed digest manifest; an operator-runnable verification command; a test
that proves reproducibility rather than asserting it in prose.

**Non-Goals:** goreleaser, Helm, Sigstore/cosign, transparency logs, SBOM, OS packages, notarization, CI
tag automation.

## Decisions

### Detached ed25519 over a manifest, not a new signing toolchain

The platform already signs feeds, response intents and risk publications with ed25519, and operators
already handle its keys. Adding cosign here would introduce a second signing story, a network dependency,
and a keyless trust root that is a *different* trust decision rather than a stronger version of this one.
Keyless signing is genuinely better for public distribution and is worth its own ticket; it is not a
prerequisite for artifacts being verifiable at all.

Signing the **manifest** rather than each artifact is deliberate: one signature covers the *set*, so an
artifact cannot be added to a release unnoticed. Per-artifact signatures verify each file and say nothing
about which files should exist.

### Reproducibility is the property the signature depends on

`-trimpath` (no build-machine paths), `CGO_ENABLED=0` (no host toolchain variance), `-buildvcs=false`
(VCS state is recorded in the manifest, not baked into binaries where it varies with a dirty tree), and
version metadata passed explicitly via `-ldflags -X`.

Without reproducibility a signature attests only that the signer had *a* binary. With it, anyone can
rebuild the commit and confirm the artifact corresponds to the source — which is the claim a security
product should be able to support about itself. Hence the test builds twice and compares, rather than the
README claiming it.

### Verification names what failed, and reports extras

Three failure modes, all reported distinctly: a digest mismatch (names the artifact), a signature mismatch
(the manifest was altered), and a file present but unnamed. The last matters most and is the easiest to
skip: a verifier that only checks the files it was told about will happily ignore an extra binary dropped
into the directory.

### The key is a path, supplied at release time

`OPENSHIELD_RELEASE_KEY` names a file; the release output contains only the public key and the signature.
The same shape as every other key in this project, and it keeps the private key out of the repository and
out of the artifact set by construction rather than by discipline.

## Risks / Trade-offs

- **A stolen signing key signs anything** → true of any signing scheme; reproducibility bounds it, because
  a signed artifact that does not rebuild from source is detectable by anyone who checks.
- **Go toolchain version affects output** → the toolchain version is recorded in the manifest, so a
  mismatch is diagnosable instead of mysterious.
- **No transparency log** → a signature proves origin, not that the release was ever published; stated,
  and the reason a log is its own ticket.
- **Building twice in a test costs time** → scoped to one command rather than the whole tree.

## Migration Plan

Additive: new targets and a new package. Nothing existing changes.

## Open Questions

- Whether keyless signing (Sigstore) should replace or accompany the ed25519 key once there is a public
  distribution channel — deliberately not decided by shipping this.
