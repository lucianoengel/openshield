## Context

Every timestamp this needs already exists, because SOAR-2 (D250) recorded them for exactly this purpose
and made the lifecycle forward-only so they would stay meaningful. `incidents` carries `first_seen`
(earliest contributing alert), `created_at` (when correlation raised it), `acknowledged_at`, and
`transitioned_at` + `state` (the last lifecycle move). So there is no migration here: the ticket is
reading what was carefully stored.

`MetricsHandler` is PLAT-4's hand-written Prometheus exposition — deliberately dependency-free, counters
only, no database access. This adds the first metrics that require a query.

## Goals / Non-Goals

**Goals:**
- Detection latency, MTTA and MTTR as three separate measurements.
- Prometheus histograms (buckets + `_sum` + `_count`) and an analyst report with percentiles.
- The excluded population reported next to every average.
- Fix the `acknowledged_at` gap so MTTA is computable for every incident a human moved.

**Non-Goals:**
- Per-analyst aggregation (see the decision below).
- SLA targets, breach alerting, or thresholds — an alert over these histograms is the operator's to write,
  and a built-in target would be a number invented here rather than chosen by whoever runs the SOC.
- Per-severity or per-domain splits in this increment.
- Backfilling `acknowledged_at` for incidents transitioned before this change.
- Incrementally maintained counters.

## Decisions

### Three durations, kept apart

Merging them would produce one flattering-or-damning number that answers no question. Split:

| Metric | Formula | Whose performance |
|---|---|---|
| detection latency | `created_at − first_seen` | the platform's (correlation interval, ingest lag) |
| time to acknowledge | `acknowledged_at − created_at` | the analyst's |
| time to resolve | `transitioned_at − created_at` where `state='closed'` | the response process's |

MTTA measured from `created_at` and not `first_seen` is the deliberate part: an analyst cannot acknowledge
an incident that does not exist yet, so charging them for the correlation window would make MTTA a
function of `OPENSHIELD_CORRELATE_INTERVAL`. That lag is real and worth seeing, which is why it gets its
own metric instead of being hidden inside another one.

MTTR uses `transitioned_at` because the lifecycle is forward-only and `closed` is terminal — the last
transition of a closed incident IS its closure. That is only true *because* of the forward-only
constraint, which is the constraint paying for itself.

### Fix `acknowledged_at`, do not work around it

`TransitionIncident` never stamped `acknowledged_at`, so `open → triaged` left it NULL forever and that
incident was permanently unmeasurable. The workaround would have been to fall back to `transitioned_at`
when the ack is missing — which invents a measurement, conflating "acknowledged at" with "moved at" for
some incidents and not others.

Instead the transition stamps it, with `COALESCE(acknowledged_at, now())` and
`COALESCE(NULLIF(acknowledged_by,''), $operator)` inside the same UPDATE. Two properties fall out:
first-ack-wins (SIEM-11b) is preserved because an existing value is never replaced, and the stamp is
atomic with the transition, so a refused (backward) transition records nothing.

Pre-existing rows are NOT backfilled. Inventing an acknowledgement time for an incident nobody recorded
one for is fabricating a measurement, the same reason migrations 028/029 refused to backfill entities and
evidence. Those incidents are counted as excluded.

### The excluded population is part of the measurement

MTTA over acknowledged incidents and MTTR over closed ones are both averages over a self-selecting
subset — and the selection is correlated with the thing being measured (the incidents nobody got to are
exactly the ones that would look worst). Reporting `excluded` next to each is what stops "MTTA 4 minutes"
from being read as fleet performance when it covers 3 of 200 incidents.

### One query per scrape, and a scrape that never fails

A single aggregate over `incidents` per scrape, with a short timeout. On any error the handler emits the
counters and omits the histograms rather than returning non-200: a metrics endpoint that fails takes
alerting down with it, turning a reporting problem into an outage in the system that would have reported
it. Correct-but-not-free on a very large incident table; incremental maintenance is the fix if that
arrives, and it is not needed now.

### No per-analyst aggregation

Technically trivial — the operator is on every row — and deliberately not done. Attribution on an incident
serves accountability for a specific decision. The same data aggregated into a per-person score is a
workforce-surveillance product, which is the thing this project's privacy posture (D20/L1) exists to
refuse, and it would be applied to the very people running the tool. Stated in the spec so a later
contributor sees it was a decision rather than an omission.

## Risks / Trade-offs

- **The numbers flatter a quiet fleet** → the excluded counts are reported alongside; a small
  acknowledged sample is visible.
- **A per-scrape aggregate on a large table** → bounded by the existing state index for now; named as the
  thing to revisit rather than pre-optimised.
- **MTTR ignores incidents that are contained but never formally closed** → correct, and the excluded
  count says how many. Treating `contained` as resolved would encode a policy this code does not own.
- **Histograms are hand-emitted** → the bucket/sum/count consistency is asserted by test, since there is
  no client library enforcing the format.

## Migration Plan

No schema change. The `acknowledged_at` fix is forward-only and affects transitions made after deployment;
existing NULLs stay NULL and are reported as excluded.

## Open Questions

- Whether a per-severity split is worth the cardinality on the Prometheus side — deferred until someone
  has an alert they cannot write without it.
