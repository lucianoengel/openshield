# Release verification must be able to check WHO signed, not only that someone did

## Why

`openshieldctl verify-release` reads the public key out of the same directory it is verifying
(`release-key.pub`, alongside `SHA256SUMS.json` and its signature). Every tampering scenario it
catches — a modified artifact, an artifact added after signing, a removed one, a manifest rewritten
to match a swapped binary — it catches correctly. What it cannot catch is the attacker who re-signs
the whole set with a key of their own and replaces the shipped public key. The digests then match a
manifest signed by a key that is present in the directory, and verification passes.

This is demonstrated, not theorised: `TestVerificationWithoutAPinnedKeyIsIntegrityOnly` performs
exactly that substitution today and the command reports success.

The gap matters because of what the artifact is. The thing being verified runs as root on every
endpoint, and PLAT-6 exists so that an operator can establish it corresponds to the source. An
operator who runs `verify-release` and sees "verified 4 artifacts" reasonably believes they have
checked that the project signed this. They have checked that *the download is internally
consistent*, which any attacker who can modify the download can arrange.

## What Changes

- `verify-release` gains `--key <path>`, an ed25519 public key the operator obtained OUT OF BAND.
  When supplied, the manifest signature is checked against THAT key and the key file inside the
  release is ignored — a release re-signed with any other key is refused.
- When `--key` is not supplied, behaviour is unchanged EXCEPT that the command says what it did and
  did not establish, on stderr, every time. Silence about the limit is what turns it into a false
  belief; the operator is told that integrity was checked and authenticity was not, and how to
  check authenticity.
- The key actually used is reported (its fingerprint), so two operators comparing notes can tell
  they verified against the same key rather than each against whatever shipped to them.
- No change to `release-manifest`, to the manifest format, or to the signature. This adds a way to
  check a release, and removes none.

## Impact

- Affected specs: `packaging`
- Affected code: `cmd/openshieldctl/release.go`, `internal/release/release.go`
- No proto change, no migration, no new dependency.
- Existing releases remain verifiable both ways: a release signed before this change verifies
  unchanged without `--key`, and verifies against a pinned key if the operator has one.
