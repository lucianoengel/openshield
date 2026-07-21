## Context

Probed: FAN_CLASS_NOTIF|FAN_REPORT_DFID_NAME init+mark+read+name-extraction WORKS unprivileged on
the host; permission mode and open_by_handle_at do NOT (need init-ns CAP_SYS_ADMIN /
CAP_DAC_READ_SEARCH). For a per-directory mark the DFID_NAME record's name is relative to the
watched dir, so path = dir/name with no handle resolution. The engine (D48) takes a file-path Event.

## Goals / Non-Goals

**Goals:**
- A notify-mode per-directory connector producing FILE_MODIFIED/CREATED Events with path dir/name.
- Pure event parsing, unit-tested; a live watch test; a kernel-event→audit e2e through the engine —
  all unprivileged, running here.
- Record the probed privilege limits.

**Non-Goals:**
- Blocking (permission mode, privileged, deferred); FID resolution / recursive marks (privileged);
  full agent assembly.

## Decisions

### Parse is a pure function
`parseEvent(watchDir string, raw []byte) (*corev1.Event, int, bool)` decodes the
`fanotify_event_metadata` + info records, finds the `FAN_EVENT_INFO_TYPE_DFID_NAME` record, extracts
the name, and builds an Event `{kind from mask, filesystem target resolved_path = dir/name, pid via
subject? no — pid is not a pseudonymous subject}`. Returns the consumed length so a buffer with
multiple events is walked. Pure over bytes → unit-testable with a captured/synthetic layout.

Kind mapping: FAN_CREATE → FILE_CREATED; FAN_MODIFY/FAN_CLOSE_WRITE → FILE_MODIFIED.

### Watcher over the fd
`Watcher{ dir string; fd int }`, linux-tagged. `Open(dir)` inits fanotify + marks the dir. `Next(ctx)`
polls (with the ctx deadline) and reads one event, returning the parsed Event; a record with no
DFID_NAME is skipped. `Close()` closes the fd. Non-linux `Open` returns `ErrUnsupported` (loud, like
the sandbox).

### Path = dir/name, no privileged resolution
Because the mark is per-directory, the event's name is the basename in that dir, so
`resolved_path = filepath.Join(dir, name)`. This sidesteps open_by_handle_at entirely for the
common watch. A recursive/filesystem mark (parent is a subdir) would need handle resolution
(privileged, unavailable) — out of scope, stated.

### Tests, all unprivileged and running here
1. `parseEvent` unit test over a byte layout (deterministic).
2. Live: Open a temp dir, write a file, `Next` returns an Event with path = that file. Runs here.
3. e2e: Open a temp dir, write a file with a seeded CPF, feed the connector's Event to the engine
   (real worker binary + real Postgres) → verifiable ledger entry. A genuine kernel-event → audit
   run, unprivileged.

## Risks / Trade-offs

- **Per-directory only (no recursion).** Recursion needs FID resolution (privileged, unavailable).
  Stated; the shipped agent watches configured dirs, which is the per-dir case.
- **No blocking.** Notify mode is observe-only, which is exactly Phase 1 (D1). Blocking is the
  deferred privileged path.
- **Event parsing uses unsafe/binary over kernel structs.** Bounded, reviewed, and unit-tested
  against a fixed layout; the live test cross-checks against the real kernel.
- **pid is available but not recorded as subject.** The Event subject is pseudonymous (D23); a raw
  pid is not that. The connector records the file path (an Event target), not the pid as identity.
