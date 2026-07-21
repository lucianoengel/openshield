# Tasks — enforcers do not follow symlinks

## 1. safeio

- [x] 1.1 `internal/enforcers/safeio/safeio_unix.go` (`//go:build unix`): `ReadRegularNoFollow(path)` opens `O_RDONLY|O_NOFOLLOW`, fstats, requires a regular file, reads via the fd.
- [x] 1.2 `internal/enforcers/safeio/safeio_other.go` (`//go:build !unix`): lstat-reject a symlink, require a regular file, then read (best-effort fallback).

## 2. Route the enforcers through it

- [x] 2.1 `encryptlocal.EnforceTarget`: replace `os.ReadFile(target)` with `safeio.ReadRegularNoFollow(target)`.
- [x] 2.2 `quarantine.fsMover.Move`: replace the fallback `os.ReadFile(src)` with `safeio.ReadRegularNoFollow(src)`.

## 3. Tests (guards, each mutation-tested)

- [x] 3.1 **safeio test**: a regular file reads fine; a SYMLINK is refused (does not read the destination); a directory/fifo is refused.
- [x] 3.2 **encryptlocal test**: a target swapped for a symlink to a secret file is REFUSED — the secret's content is neither read nor written into the (would-be) encrypted output.
- [x] 3.3 **quarantine test**: the fallback copy refuses a symlinked source rather than copying the destination.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D65: enforcers use O_NOFOLLOW + regular-file check (safeio), refusing a swapped symlink/non-regular target loudly; closes the final-component TOCTOU arbitrary-file-read; parent-dir-swap (openat2) and fd-from-classification are follow-ups.
- [x] 4.2 `openspec validate enforcer-no-symlink --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| ReadRegularNoFollow follows symlinks (O_NOFOLLOW neutralized) | `TestReadRegularNoFollow`, `TestEncryptRefusesSymlinkTarget` |
| RefuseNonRegular accepts a non-regular target | `TestQuarantineRefusesSymlinkSource` |

**Honest note:** removing only the EXPLICIT symlink check from RefuseNonRegular was
masked — a symlink is also not a regular file, so the IsRegular check still refuses
it (defense in depth). The mutation that removes BOTH checks is caught.

The file enforcers no longer follow a symlink at the flagged path: encryptlocal
reads via O_NOFOLLOW + a regular-file check and refuses a swapped symlink (the
secret is neither read nor encrypted); quarantine refuses a non-regular source
outright. Residual documented: parent-directory-component swap (openat2) and an
fd carried from classification are follow-ups.
