## Context

`intParam(q, key, def) (int, error)` (correlate.go) is the SEC-8 validator: empty → default, non-integer
or `<= 0` → error (→ 400 at the handler). `queryInt(r, key, def) int` (operator_read.go) is the older
silent variant: any parse failure or non-positive value → default, no error. The `/incidents` and
`/alerts` handlers call `queryInt` for `limit`; every other operator param already uses `intParam`.

## Goals / Non-Goals

**Goals:** make a malformed `limit` a 400 on both list endpoints; delete the silent helper so it cannot
be reused.

**Non-Goals:** changing the cap (already enforced in `RecentIncidents`/`RecentPeerAlerts` at
`maxSearchLimit`), the default (100), or any other endpoint's behavior.

## Decisions

1. **Reuse `intParam`, don't add a new validator.** Both handlers already have `r.URL.Query()` (or can
   take it), and `intParam` returns exactly the needed error. `/incidents` already builds `q :=
   r.URL.Query()`; `/alerts` gets one line.
2. **Delete `queryInt`.** After both callers move to `intParam`, `queryInt` is unused. Removing it
   prevents the silent-default pattern from being copied into a new endpoint — the SEC-8 lesson is that a
   silent default reads as authoritative, so the helper that enables it should not exist.
3. **Absent `limit` keeps the default (100).** SEC-8 rejects *malformed* input, not *absent* input — an
   omitted limit is a valid "use the default" request, unchanged.

## Risks / Trade-offs

- **A client that today relies on a garbage `limit` being silently ignored now gets a 400.** This is the
  intended stricter behavior; the endpoints are operator-only (RoleAnalyst/RoleOperator), so the blast
  radius is an operator's own query, and a 400 with a clear message is more honest than a silently
  truncated list.
