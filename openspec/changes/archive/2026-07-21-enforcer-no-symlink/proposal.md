## Why

Audit finding #3, verified: the quarantine and encrypt-local enforcers act on a
re-resolved path STRING between classification and enforcement, FOLLOWING
symlinks. `encryptlocal.EnforceTarget` does `os.ReadFile(target)` (follows a
symlink → reads a file the agent should never read), and quarantine's fallback
copy does `os.ReadFile(src)` likewise. A non-root local user — the exact
careless/malicious insider the threat model addresses — can race a symlink swap
into the flagged path in the window between the pipeline classifying the file and
the enforcer acting, redirecting the enforcer's read onto an attacker-chosen file.
A defensive mechanism becomes an arbitrary-file-read primitive, and D49/D57's
"atomic/idempotent" correctness says nothing about WHICH file is acted on.

## What Changes

- A small `internal/enforcers/safeio` package: `ReadRegularNoFollow(path)` opens
  the target WITHOUT following a final-component symlink (`O_NOFOLLOW`) and only if
  `fstat` shows a REGULAR file (not a symlink, device, fifo, or directory), reads
  via the fd, and refuses otherwise. A swapped symlink makes the enforcer REFUSE
  — a loud, auditable failure (D49/D14), never a silent redirect.
- `encryptlocal`'s target read and `quarantine`'s fallback-copy read route through
  it.
- Cross-platform: a `//go:build unix` implementation using `syscall.O_NOFOLLOW`,
  and a `!unix` fallback that lstat-rejects a symlink before reading (best-effort;
  the endpoint is Linux, documented).

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `enforcement`: the file enforcers no longer follow a symlink at the flagged
  path — a target swapped for a symlink (or a non-regular file) is refused, not
  acted on, closing the classification→enforcement TOCTOU's arbitrary-file-read.

## Impact

- New: `internal/enforcers/safeio` (unix + fallback); tests. Changed reads in
  `encryptlocal` and `quarantine`. Docs (D65).
- HONEST residual, documented: `O_NOFOLLOW` closes the FINAL-component symlink
  swap; a full defense against a PARENT-directory component swap needs `openat2`
  `RESOLVE_NO_SYMLINKS` or a dir-fd-relative operation (Linux-specific), and the
  strongest fix carries an fd from classification through enforcement (a bigger
  pipeline change) — both noted as follow-ups. Respects D49 (contain after
  detection) and D16.
