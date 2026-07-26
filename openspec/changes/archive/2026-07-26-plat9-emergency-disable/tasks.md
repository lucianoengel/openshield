## 1. The switch
- [x] 1.1 `internal/core/killswitch.go`: `KillSwitch` with `Engage(reason, source)`, `Disengage(source)`,
      `Engaged() (bool, string)`, `Suppressions` counter, and `SuppressEnforcement(d)` deciding per
      Decision. Absence and read failure both mean NOT engaged.
- [x] 1.2 A file-backed source polled on an interval; an unreadable file logs and leaves the switch as is.

## 2. Both call sites
- [x] 2.1 `internal/engine` and `internal/gateway` consult the SAME switch before `Enforce`, record the
      suppression, and continue the pipeline unchanged.

## 3. Tests
- [x] 3.1 Engaged → an enforcing decision reaches NO enforcer; an alert-only decision is unaffected;
      disengaging restores enforcement (**mutation:** consult the switch only in the gateway → the engine
      still enforces → FAILS).
- [x] 3.2 The decision is still recorded while suppressed (**mutation:** drop the event before the
      pipeline → FAILS).
- [x] 3.3 Suppressions are counted and carry the reason (**mutation:** report state without counting →
      FAILS).
- [x] 3.4 A missing file, and an unreadable one, both leave enforcement ON (**mutation:** treat a read
      error as engaged → FAILS).

## 4. Gate and land
- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 4.2 Record D265; roadmap PLAT-9 → increment 1 done, the rest named.
- [x] 4.3 Sync specs and archive.
