# NIPS-7: bound the listener admission rate (ledger-flood defense)

## Why

A connector listener that feeds the pipeline mints a ledger write per accepted datagram. The DNS
listener accepts UDP queries with attacker-chosen names and a SPOOFABLE source, so a query flood
grows the audit ledger at wire speed with attacker-controlled content — a ledger-poisoning
denial-of-service, and the crown-jewel ledger is exactly what must stay clean. The panic-recovery
half of the shared listener contract landed with ENG-2; the admission rate limit is the remaining
new defense.

## What Changes

- **A shared token-bucket rate limiter** (`internal/connectors/limiter`): a GLOBAL bucket (not
  per-source, which spoofing defeats) admitting a burst then a sustained rate, with an injectable
  clock for deterministic tests.
- **The DNS listener rate-limits admission**: a datagram beyond the rate is dropped BEFORE it mints
  a pipeline event/ledger write, counted separately (`RateLimited`), so a flood is bounded and
  observable. On by default with a generous rate (tunable/disablable via the `Limiter` field).

## Impact

- Affected specs: `dns-connector`
- Affected code: `internal/connectors/limiter/limiter.go` (new), `internal/connectors/dns/listen.go`.
- Not in scope (stated): applying the shared limiter to the syslog and SMTP listeners (the same
  contract — a mechanical follow-up now the limiter exists; DNS is the flagged concrete risk); a
  per-source limit (spoofing defeats it — the global bucket is the robust choice); sampling instead
  of dropping (dropping is simpler and the ledger-write bound is the goal); the full extraction of
  deadlines/caps into one contract type (SMTP already has its own caps from NIPS-3-SMTP).
