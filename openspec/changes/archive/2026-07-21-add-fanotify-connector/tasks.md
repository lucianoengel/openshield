## 1. Connector

- [x] 1.1 `internal/connectors/fanotify` (linux): `parseEvent(dir, raw) (*Event, consumed, ok)` —
      pure; decode metadata + DFID_NAME, kind from mask, resolved_path = dir/name
- [x] 1.2 `Watcher.Open(dir)` (FAN_CLASS_NOTIF|FAN_REPORT_DFID_NAME + mark), `Next(ctx)`, `Close()`;
      non-linux `Open` → ErrUnsupported

## 2. Tests (unprivileged, here)

- [x] 2.1 **Test**: `parseEvent` over a fixed byte layout → correct mask + name. `TestParseEvent`
- [x] 2.2 **Test** (live): Open a temp dir, write a file, Next returns an event with that path.
      `TestWatchRealFile`
- [x] 2.3 **Test** (live e2e): a seeded-CPF file in a watched dir → connector event → engine (real
      worker + Postgres) → verifiable audit. `TestFanotifyToAudit`

## 3. Docs

- [x] 3.1 Note in `docs/decisions.md` (new D-number): notify-mode per-directory observe works
      unprivileged (path=dir/name); permission mode + FID resolution privileged (probed unavailable)
- [x] 3.2 Validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| wrong kind mapping (CREATE→MODIFIED) | `TestParseEvent` |
| wrong name byte-offset | `TestParseEvent` |

All three tests pass HERE, UNPRIVILEGED: `ParseEvent` over a fixed byte layout;
`TestWatchRealFile` — a real file write produces an event with the right path via
live notify-mode fanotify; and `TestFanotifyToAudit` — a real file with a seeded
CPF written to a watched dir flows connector → engine (real worker + real
Postgres) → ALERT → verifiable ledger entry. This is the kernel-event → audit run
the walking skeleton fed synthetically, now from a real file change. The
privilege limits (permission mode, FID resolution) were PROBED, not assumed, and
recorded as D52.
