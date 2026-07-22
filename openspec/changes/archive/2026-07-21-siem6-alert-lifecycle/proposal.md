# SIEM-6: alert lifecycle — severity buckets and acknowledgement

## Why

A peer alert (D54) had a continuous `risk_score` but no triage state. An operator facing a
stream of alerts could not prioritize (which are the urgent ones?) nor mark one handled
(which have I already triaged?) without opening a full investigation case — a heavyweight,
four-eyes-to-close artifact. Correlation (D131) and search (D132) built the read side of a SIEM;
what was missing is the triage loop over the alerts themselves: **prioritize by severity, ack
the noise, work the rest.**

## What Changes

- **Severity** — a pure, derived triage bucket over the risk score (`critical ≥ 0.90`,
  `high ≥ 0.75`, `medium ≥ 0.50`, else `low`). Not stored, so it cannot drift out of sync with
  the score and a threshold change re-buckets history without a migration. Surfaced on every
  `PeerAlert` and `Incident`, and usable as a `min_severity` filter (translated to a risk floor,
  combined with an explicit `min_risk` by taking the stronger of the two).
- **Acknowledgement** — a lightweight per-alert state (migration 016 adds `acknowledged_at`,
  `acknowledged_by`). `AcknowledgeAlert(id, operator)` is first-ack-wins (the
  `acknowledged_at IS NULL` guard preserves the original triager), disambiguates a phantom id
  (`ErrAlertNotFound`) from an already-acked no-op, and is exposed as `POST /alerts/ack?id=N`.
  The acknowledging operator is taken from the **verified mutual-TLS client certificate**
  (like `/view`, D56) — never a request field, because an ack is an accountable action.
- **The actionable queue** — `AlertFilter` gains `UnacknowledgedOnly` and `MinSeverity`, so the
  queue an analyst works is "unacknowledged alerts at or above a severity".

This modifies the `control-plane` capability. No core interface change.

## Impact

- Affected specs: `control-plane`
- Affected code: `internal/controlplane/{severity,alert_ack}.go` (new),
  `operator_read.go` (DTO, filters, mount), `correlate.go` (incident severity),
  `enroll_http.go` (mount `/alerts/ack`), migration 016, migration-count test.
- Not in scope (stated): a full incident lifecycle beyond alert ack (assign/close already live
  as cases, D122); alert suppression/mute rules; notification on severity thresholds (D83 emits
  on detection already); configurable severity thresholds (compiled constants for now — a
  policy-driven scale is a follow-up).
