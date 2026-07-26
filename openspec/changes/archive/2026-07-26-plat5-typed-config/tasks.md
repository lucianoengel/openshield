## 1. The model

- [x] 1.1 `internal/config`: `Kind` (string|int|duration|bool|secret), `Field{Key, Kind, Default,
      Description, Parse, Validate}`, `Source` interface, `envSource`, `fileSource`, `Resolver` with
      env→file→default precedence.
- [x] 1.2 `FieldError{Key, Value, Reason}` and a `Validate()` that returns ALL of them.
- [x] 1.3 `Describe()` deriving the schema from the field declarations; `Effective()` returning each
      value with its ORIGIN, secrets redacted to set/unset.

## 2. Tests

- [x] 2.1 Env overrides file; file overrides default; origin is reported correctly.
- [x] 2.2 A malformed duration/int is an ERROR naming the field, never a silent default (**mutation:**
      fall back to the default on a parse failure → FAILS).
- [x] 2.3 Several invalid fields are ALL reported (**mutation:** return on the first → FAILS).
- [x] 2.4 A secret's value appears in NO output: not `Describe()`, not `Effective()`, not the subcommand
      (**mutation:** include the value in Effective → FAILS).
- [x] 2.5 Every declared field is present in `Describe()` and every described field is readable —
      asserted in BOTH directions, so a field cannot exist in one and not the other.

## 3. Adoption

- [x] 3.1 Declare the server's fields and read them through the resolver; fail fast at boot on any
      `FieldError`.
- [x] 3.2 `openshield-server config` printing the schema + effective values (redacted).
- [x] 3.3 A test asserting every `OPENSHIELD_*` variable read by `cmd/openshield-server` is declared —
      the guard against a field drifting back out of the schema.

## 4. Gate and land

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 4.2 Record D262 (including the UI constraint that shaped it); roadmap PLAT-5 → DONE with residuals.
- [x] 4.3 Sync specs and archive.
