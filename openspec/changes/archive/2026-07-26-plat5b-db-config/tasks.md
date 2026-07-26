## 1. Scope and store
- [x] 1.1 `Scope` on `Field`; classify all server fields; a test bounding the bootstrap set.
- [x] 1.2 Migration `036_config_settings.sql`: `config_settings`, `config_revisions`, `config_changes`.
- [x] 1.3 `DBSource` (immutable snapshot + atomic swap) and `Watcher` polling the max revision.
- [x] 1.4 Resolver: dynamic → DB then default; bootstrap → env/file then default; env on a dynamic field
      is IGNORED and reported, unless break-glass names it.

## 2. Revisions
- [x] 2.1 `ApplySettings(ctx, author, note, changes)` — validate all, refuse bootstrap and secret keys,
      refuse unknown keys, write revision + diff + current in ONE transaction.
- [x] 2.2 `Revisions`, `RollbackTo` (a new revision restoring old values, never deleting history).

## 3. Live apply
- [x] 3.1 `retain.DynamicLoop(ctx, next func() time.Duration, fn)`.
- [x] 3.2 `RunCorrelationLoop` takes a rule PROVIDER; the server wires it from the resolver.

## 4. Tests
- [x] 4.1 A dynamic value reads from the DB; a bootstrap write is refused; an unknown key is refused.
- [x] 4.2 An invalid value refuses the WHOLE change and creates no revision (**mutation:** apply valid
      keys and skip invalid ones → FAILS).
- [x] 4.3 A secret write is refused and nothing is stored (**mutation:** allow it → FAILS).
- [x] 4.4 An env value for a dynamic field is IGNORED and REPORTED (**mutation:** let env win → FAILS);
      break-glass applies it and still reports it.
- [x] 4.5 Revision records author + per-key diff; rollback restores values as a NEW revision and keeps
      history (**mutation:** rollback deletes revisions → FAILS).
- [x] 4.6 LIVE APPLY: a running loop picks up a new value with no restart (**mutation:** capture the
      value at loop start → FAILS).

## 5. Gate and land
- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 5.2 Record D263; roadmap PLAT-5 → DONE (both increments).
- [x] 5.3 Sync specs and archive.
