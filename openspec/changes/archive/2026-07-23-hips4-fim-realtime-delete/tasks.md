## 1. The mask (`cmd/openshield-engine/fimwatch_linux.go`)

- [x] 1.1 Add `FAN_DELETE | FAN_MOVED_FROM` to the real-time watch mask (a child deleted from / moved out of a watched dir fires the same immediate re-scan as a modify). Update the comment (delete is now real-time; ADD/create stays poll-caught). Extract the mask into a named const so a test can assert it.

## 2. Tests

- [x] 2.1 (gated, VM) Low-level: init fanotify exactly as `fimWatchSource` (FID mode + the new mask), mark a temp dir, create then DELETE a file, assert a fanotify event becomes readable within a short bound → the kernel delivers `FAN_DELETE` in the unprivileged FID watch. Skip if the mark/init is unsupported.
- [x] 2.2 (gated, VM) End-to-end: baseline a temp file, run `fimWatchSource` on its dir, DELETE the file, assert an `EVENT_KIND_FILE_DELETED` arrives on the events channel within a bound well under the poll interval (real-time, not poll).
- [x] 2.3 (no kernel) Assert the mask const includes the delete bits — keeps the portable build honest.

## 3. Mutation verification

- [x] 3.1 (gated, VM) Drop `FAN_DELETE | FAN_MOVED_FROM` from the mask → test 2.2 no longer receives the `FILE_DELETED` event within the real-time bound → it FAILs. Revert.

## 4. Gate & land

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (gated tests SKIP without the kernel); proto-check clean; cross-compile clean.
- [x] 4.2 Run the gated VM tests; paste the PASS + the mutation FAIL.
- [x] 4.3 decisions.md D-entry; sync the delta into `openspec/specs/file-integrity-monitoring/spec.md`; doccheck.
- [x] 4.4 Update the roadmap: FIM real-time DELETE done (D228's deferred item); note remaining deferrals. Archive; commit; `git pull --rebase`; push.
