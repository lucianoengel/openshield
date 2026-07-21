## 1. seccomp network-deny filter

- [x] 1.1 `internal/agent/sandbox` package. `sandbox_linux.go`: `Apply()` builds a default-allow
      `seccomp.Policy` with an ActionErrno group over the network syscalls (socket, socketpair,
      connect, bind, listen, accept, accept4, sendto/recvfrom, sendmsg/recvmsg) plus ptrace;
      loads with `NoNewPrivs: true, Flag: FilterFlagTSync`
- [x] 1.2 `sandbox_other.go` (non-linux): `Apply()` returns `ErrUnsupported`, never nil
- [x] 1.3 Call `sandbox.Apply()` in `cmd/openshield-worker` BEFORE the read loop; log prominently
      if it returns `ErrUnsupported`, and fail hard on any other error (a filter that errored is
      not a sandbox)

## 2. Tests — the sandbox

- [x] 2.1 **Test** (linux): after `Apply()`, `unix.Socket(AF_INET,...)` fails. `TestSocketDeniedAfterApply`
- [x] 2.2 **Test** (linux): a socket attempted from a goroutine on another thread also fails.
      `TestFilterCoversAllThreads`
- [x] 2.3 Run these in a subprocess/helper so the filter does not poison the rest of the test
      binary (seccomp is irreversible for the process)

## 3. Decompression-bomb guard

- [x] 3.1 `sandbox.DecompressGuard` wrapping an `io.Reader`: bounds ratio (out/in), absolute output
      size, and (via an explicit depth counter) nesting depth; returns an error at the moment a
      bound is crossed, before the caller gets the over-limit bytes
- [x] 3.2 **Test**: a high-ratio expansion (e.g. gzip of megabytes of zeros) hits the ratio/size
      cap and errors rather than delivering the bytes. `TestBombHitsGuard`
- [x] 3.3 **Test**: nesting beyond the depth cap is rejected. `TestNestingDepthRejected`

## 4. cgroup limits — specified for the supervisor

- [x] 4.1 Document required cgroup limits (`MemoryMax`, `MemorySwapMax=0`, `CPUQuota`, `TasksMax`)
      in the sandbox/worker package doc and provide a systemd drop-in fragment under `deploy/`
- [x] 4.2 State plainly that these are supervisor-enforced, not in-process — a Go process cannot
      reliably self-limit its cgroup without privilege, and pretending to would be theatre

## 5. Docs

- [x] 5.1 Record the seccomp denylist decision in `docs/decisions.md` (new D-number): worker
      self-applies a network-deny filter before reading input; denylist now, allowlist later
- [x] 5.2 Mark T-012 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| seccomp denylist emptied | `TestSocketDeniedAfterApply` — socket allowed after Apply |
| decompression absolute cap disabled | `TestBombHitsGuard` — fails FAST (bounded wait), not a hang |

**Two test-quality bugs the mutation pass found and fixed.** (1) The seccomp
availability probe originally shared the socket-denial outcome with the test it
guarded, so an empty denylist made the test SKIP instead of FAIL — masking the
regression. Split into an `apply-only` child probe that checks whether seccomp
loads at all, independent of denial. (2) `TestBombHitsGuard` set inputSize=1024,
so the ratio bound caught the bomb even with the absolute cap disabled; set to 0
to isolate the absolute cap, and wrapped in a bounded wait so a missing cap fails
in 10s rather than hanging the suite on the binary timeout.

The real seccomp filter blocks `socket()` after `Apply()`, including from a
goroutine on another thread (TSYNC coverage), confirmed by subprocess tests that
skip LOUDLY where seccomp is unavailable. The privileged binary gains no seccomp
or parser dependency (`check-agent-deps.sh`). cgroup limits ship as a systemd
drop-in under `deploy/`, specified for the supervisor, not faked in Go.
