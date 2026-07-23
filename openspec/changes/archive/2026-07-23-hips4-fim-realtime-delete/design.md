# Design — real-time FIM deletion

## The one-line change, and why it is safe

The real-time watch (`fimWatchSource`) already initializes fanotify with `FAN_REPORT_DFID_NAME` (the
unprivileged FID mode, D52) and marks each watched directory. Its mask is:

```
FAN_MODIFY | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD
```

`FAN_DELETE` and `FAN_MOVED_FROM` are **directory-entry events**: they fire on a marked directory when a
child is unlinked from it (or renamed out of it). They are exactly the deletion tamper signal, and — like
the modify events — they are used here only as a *trigger*; the event contents are never parsed, so no
attacker-controlled bytes are decoded. `fim.Scan` re-diffs the baseline and reports the missing file as
`DELETED`, which `fimEvent` maps to `EVENT_KIND_FILE_DELETED`. So the detector, the event, and the metadata-
only classification (D223) are all already in place; the mask is the only gap.

New mask:

```
FAN_MODIFY | FAN_CLOSE_WRITE | FAN_DELETE | FAN_MOVED_FROM | FAN_EVENT_ON_CHILD
```

Directory-entry events are reported against the marked directory itself (not a child fd), so they compose
with the existing dir marks with no structural change. `FAN_MOVED_FROM` is included because a rename OUT of
the watched directory removes the file from the protected set exactly as a delete does. `FAN_MOVED_TO` /
`FAN_CREATE` (an ADD) are deliberately left to the poll — an added file is a weaker tamper signal and the
poll already reports it.

## The kernel-gated unknown

Whether the **unprivileged** FID watch delivers `FAN_DELETE` on a directory mark is a kernel behavior that
must be confirmed on real hardware (kernel 6.8): unprivileged fanotify (`FAN_REPORT_FID`, since 5.13)
supports directory-entry events, but this is precisely the kind of assumption the project's "verifies
against its own assumptions" failure mode punishes — so it is proven on the VM, not asserted.

## Testing

- **(A) gated real-kernel VM test** (`requireFanotifyDelete`: skip unless linux and the mark succeeds) —
  the low-level proof: init the watch exactly as `fimWatchSource` does (FID mode, the new mask), mark a temp
  dir, create then **delete** a file in it, and assert a fanotify event becomes readable. This confirms the
  kernel delivers `FAN_DELETE` in the unprivileged FID mode.
- **(B) gated real-kernel VM test** — the end-to-end proof: build a baseline over a temp file, run
  `fimWatchSource` on its directory, delete the file, and assert an `EVENT_KIND_FILE_DELETED` arrives on the
  events channel within a short bound (well under the poll interval). This proves the delete is caught in
  real time, not by the poll.

  **Mutation:** drop `FAN_DELETE | FAN_MOVED_FROM` from the mask → test (B) no longer receives the
  `FILE_DELETED` event within the real-time bound (only the poll would catch it, which the test does not
  run) → it FAILs. Proves the mask addition is load-bearing.

Both tests are gated (skip without the kernel), so `make all` stays green locally; they run on the VM via
`go test -c` + scp + `sudo` (root not strictly required for the unprivileged watch, but the VM is where the
capable kernel lives). A no-kernel unit assertion keeps the portable build honest: the mask constant
includes the delete bits.
