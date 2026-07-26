## Why

SOAR-2 (D250) made the incident lifecycle forward-only *specifically* so response time would stay
measurable — "MTTA/MTTR are derived from these timestamps, and a lifecycle that can move backwards makes
them unmeasurable" is the reason recorded for the constraint. The timestamps have been accumulating ever
since and nothing reads them. A SOC that cannot say how long it takes to acknowledge and resolve an
incident cannot tell whether any of this is working.

Building it surfaced a real defect in the data it depends on: `TransitionIncident` advancing an incident
from `open` straight to `triaged` (or further) never stamps `acknowledged_at`. Those incidents are
permanently unmeasurable for time-to-acknowledge — the exact outcome the forward-only constraint exists to
prevent.

## What Changes

- **`acknowledged_at` is stamped by the first move off `open`**, whichever route takes it there.
  `AcknowledgeIncident` already did this; `TransitionIncident` did not, so an operator who triaged
  directly erased their own response time. The stamp uses `COALESCE`, so an existing acknowledgement is
  never overwritten — first-ack-wins (SIEM-11b) is preserved.
- **Three durations, computed from timestamps that already exist**, and deliberately kept apart rather
  than merged into one "response time":
  - **detection latency** = `created_at − first_seen` — how long the platform took to raise an incident
    after its first contributing alert. This is *our* lag, not the analyst's.
  - **MTTA** = `acknowledged_at − created_at` — how long a human took to pick it up.
  - **MTTR** = `transitioned_at − created_at`, over incidents in state `closed` only.
- **Prometheus histograms** on the existing `/metrics` endpoint (PLAT-4's hand-written, dependency-free
  exposition), plus `_sum`/`_count` so a rate can be computed.
- **`GET /report/response`** (analyst tier) — counts, p50/p90 per duration, in JSON.
- **A visible sample-bias counter.** MTTA can only be computed over incidents that were acknowledged, and
  MTTR only over incidents that were closed. Both reports expose how many incidents are *excluded*, so a
  flattering mean over a small acknowledged subset is legible as such instead of being read as fleet
  performance.
- A metrics query failure **never fails the scrape**: the counters still serve and the histograms are
  omitted. A metrics endpoint that 500s takes alerting down with it.

## Capabilities

### New Capabilities
- `response-metrics`: incident response-time measurement (detection latency, MTTA, MTTR) derived from the
  forward-only lifecycle, exposed as Prometheus histograms and an operator report.

### Modified Capabilities
- `control-plane`: the first transition off `open` stamps the acknowledgement timestamp regardless of
  which route made it, so time-to-acknowledge is measurable for every incident a human touched.

## Impact

- **New code**: `internal/controlplane/responsemetrics.go` (the aggregate query + report),
  additions to `MetricsHandler`, one new operator route.
- **No migration.** Every timestamp this needs already exists (`created_at`, `first_seen`,
  `acknowledged_at`, `transitioned_at`) — this ticket reads what SOAR-2 was careful to record.
- **No new dependency**: histograms are emitted in the existing hand-written exposition format.
- **Honest scope**: no per-analyst breakdown — attributing response times to named operators turns an
  operational metric into workforce surveillance, which is the thing D20's privacy posture exists to
  refuse; the attribution stays on the incident for accountability, it is not aggregated into a
  leaderboard. No SLA/target configuration or breach alerting (an alert on these histograms is the
  operator's to write). No per-severity or per-domain split in this increment. No backfill: incidents
  transitioned before this change keep their missing `acknowledged_at` and are counted as excluded rather
  than having a timestamp invented for them. The aggregate is computed per scrape rather than
  incrementally maintained, which is correct but not free on a very large incident table.
