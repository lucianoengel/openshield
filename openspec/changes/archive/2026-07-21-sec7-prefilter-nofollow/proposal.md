## Why

SEC-7 (P2). The inline prefilter's bounded prefix read used `os.Open`, not
`safeio.ReadRegularNoFollow` — inconsistent with the TOCTOU discipline the enforcers already
hold (D65). An attacker who swaps the flagged path for a symlink (or a special file) between
classification and the prefilter read could redirect the read onto an arbitrary file. Lower
severity (the prefilter is not yet wired to a live permission syscall), but closed before
Phase B wires inline.

## What Changes

- `safeio.OpenRegularNoFollow` — the no-follow, regular-file-only OPENER (returns the open
  file so a caller can do a BOUNDED read), refactored out of `ReadRegularNoFollow`.
- The prefilter's `openFile` uses it, so the prefix read gets O_NOFOLLOW + regular-file
  guarantees while still reading only `maxBytes`.

## Capabilities

### Modified Capabilities
- `inline-prevention`: the prefilter prefix read refuses a symlinked or non-regular target.

## Impact

- `internal/enforcers/safeio/safeio_{unix,other}.go`, `internal/agent/prefilter/decider.go`;
  `docs/decisions.md` D120.
- Proven: the prefilter refuses a flagged path swapped for a SYMLINK (mirrors the enforcer
  safeio tests), while a regular file is still read normally. Guard mutation-tested: reverting
  to `os.Open` (follows the symlink) fails the test.
- NOT in scope (stated): the parent-directory-component swap (needs openat2
  RESOLVE_NO_SYMLINKS — the documented safeio residual D65); carrying an fd from the fanotify
  producer through to the read (the strongest TOCTOU fix, tied to Phase B's permission-mode
  agent, external-gated).
