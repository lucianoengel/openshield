# Design — SIEM-6 alert lifecycle

## Severity is derived, not stored

The risk score already exists; severity is a view of it. Storing it would introduce a second
source of truth that can drift (a re-scored alert with a stale severity column) and would force a
migration to re-tune thresholds. A pure `Severity(risk) string` computed on read avoids both:
history re-buckets the instant the constants change, and there is no column to keep consistent.
The thresholds are inclusive lower bounds so the boundary is deterministic (0.90 is critical, not
"almost"); the boundaries are exactly where a bug hides, so they are what the test pins.

`min_severity` filtering reuses the same thresholds: a severity label maps to its risk floor, and
the filter applies `risk_score >= floor`. When both `min_risk` and `min_severity` are set, the
STRONGER (higher) floor wins — asking for "high" must never widen a stricter `min_risk`.

## Acknowledgement: first-ack-wins, cert-attributed

Ack is deliberately lighter than a case. A case is an investigation (assigned, noted, four-eyes
to close); an ack is "an analyst has looked at this alert". The state is two columns and the
contract is:

- **First ack wins** — `UPDATE ... WHERE id = $1 AND acknowledged_at IS NULL`. A later ack
  changes nothing and reports `newlyAcked=false`, so the original triager and time are the record.
  A mutation dropping the `IS NULL` guard lets a late ack overwrite the triager — the test's
  second-ack-by-bob asserts alice remains, so it fails.
- **Phantom vs already-acked** — both produce zero updated rows, but they mean different things.
  An existence probe disambiguates: a non-existent id is `ErrAlertNotFound` (a client mistake
  worth a 404); an existing-but-acked id is an idempotent success (a retried request is fine).
- **Attribution from the certificate** — the handler reads `operatorIdentity(r.TLS)`, never a
  request field, and refuses without a verified cert. This is the same accountable-identity rule
  as `/view` (D56): an ack that could name any operator is not accountable.

## The actionable queue

`UnacknowledgedOnly` (`acknowledged_at IS NULL`) plus `MinSeverity` compose into the queue an
analyst works. A mutation replacing the unacknowledged predicate with `true` returns acked alerts
into the queue — the test asserts the acked subject is gone, so it fails.
