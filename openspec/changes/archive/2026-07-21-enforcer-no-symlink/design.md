## Context

Enforcement is post-decision (D49): the engine hands the enforcer the target file
PATH. `encryptlocal.EnforceTarget` reads it with `os.ReadFile` (follows symlinks),
encrypts, writes a temp, renames. `quarantine.fsMover.Move` renames (which does
NOT follow a symlink source) but its cross-filesystem FALLBACK reads with
`os.ReadFile` (follows). The TOCTOU is the window between the pipeline resolving+
classifying the path and the enforcer opening it.

## Goals / Non-Goals

**Goals:**
- The enforcer never reads THROUGH a symlink at the flagged path; a swapped
  symlink or a non-regular target is refused loudly.
- Cross-platform build preserved (the endpoint is Linux; the fix is a Linux
  security control with a portable fallback).

**Non-Goals:**
- Parent-directory-component symlink protection (needs openat2/dir-fd) — a
  documented follow-up.
- Carrying an fd from classification through enforcement (the strongest fix, a
  pipeline change) — a documented follow-up.
- Changing the Decision contract or the enforce dispatch.

## Decisions

**`O_NOFOLLOW` + `fstat` regular-file check, operating on the fd.** Open the
target `O_RDONLY|O_NOFOLLOW`; if it is a symlink the open fails (`ELOOP`) → refuse.
`fstat` the fd and require a REGULAR file (reject symlink/dir/fifo/device/socket).
Read from the fd. This eliminates the symlink-follow class at the final component
in one syscall, without re-resolving the path.

**A tiny shared package, build-tagged.** `internal/enforcers/safeio` exposes
`ReadRegularNoFollow(path) ([]byte, error)`. `safeio_unix.go` (`//go:build unix`)
uses `syscall.O_NOFOLLOW`; `safeio_other.go` (`//go:build !unix`) lstats first and
rejects a symlink, then reads (best-effort — Windows is not an endpoint target,
stated). Both reject non-regular files via the returned `FileInfo`.

**Refuse, do not silently no-op.** A refusal returns an error the enforcer
surfaces; the engine audits an enforcement failure as high-severity (D14) — the
existing behaviour for any enforce error. A silent skip would be the quiet
failure D14 forbids.

## Risks / Trade-offs

- **Parent-directory swap remains.** An attacker who can swap a PARENT directory
  component for a symlink between open and any later path-based step is not
  stopped by final-component `O_NOFOLLOW`. Closing it needs `openat2`
  `RESOLVE_NO_SYMLINKS` (Linux 5.6+) or dir-fd-relative opens — a documented
  follow-up, not silently assumed solved.
- **A legitimate symlinked target is now refused.** If an operator legitimately
  watches a directory of symlinks, enforcement refuses them. That is the safe
  default (refuse the ambiguous case, loudly) and matches "contain after
  detection, never act on the wrong file."
- **The `!unix` fallback has its own small TOCTOU** (lstat then open). It is a
  best-effort for a non-endpoint platform; the real control is the unix path. Said
  plainly.
