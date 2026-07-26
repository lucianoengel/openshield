## 1. Make time-to-acknowledge measurable

- [x] 1.1 `TransitionIncident`: stamp `acknowledged_by`/`acknowledged_at` inside the same UPDATE using
      COALESCE, so the first move off `open` records it and an existing acknowledgement is never
      overwritten.
- [x] 1.2 Tests: `open → triaged` records the acknowledgement; a later transition by another operator does
      not overwrite it; a refused (backward) transition records nothing. **Mutation:** drop the COALESCE
      stamp → the directly-triaged incident has no acknowledgement → FAILS. **Mutation:** stamp
      unconditionally (no COALESCE) → the second operator overwrites the first → FAILS.

## 2. The aggregate

- [x] 2.1 `internal/controlplane/responsemetrics.go`: `ResponseMetrics(ctx)` returning, for each of
      detection latency / time-to-acknowledge / time-to-resolve, the count, p50, p90, mean and the
      EXCLUDED count. One query. No grouping by operator.
- [x] 2.2 Tests: the three durations are computed independently and correctly from seeded incidents; an
      unclosed incident contributes no MTTR and is counted as excluded; an unacknowledged incident
      contributes no MTTA and is counted as excluded. **Mutation:** report only the included count and
      drop `excluded` → FAILS.

## 3. Exposition

- [x] 3.1 `MetricsHandler`: emit three histograms (cumulative `_bucket{le=…}`, `_sum`, `_count`) in the
      existing hand-written format, with a short-timeout query; on error emit the counters and OMIT the
      histograms, never a non-200.
- [x] 3.2 `GET /report/response`, analyst tier, JSON.
- [x] 3.3 Tests: acknowledging an incident moves the ack count and its buckets; buckets are monotonic and
      `+Inf` equals `_count`; a broken aggregate still returns 200 with the counters (**mutation:** return
      an error status when the aggregate fails → FAILS).
- [x] 3.4 A test asserting no exposed series and no report field groups by operator.

## 4. Gate and land

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 4.2 Record D258 in `docs/decisions.md`, including the `acknowledged_at` defect this surfaced and the
      deliberate refusal of per-analyst aggregation.
- [x] 4.3 Update `docs/architecture-roadmap.md`: SOAR-6 → DONE with residuals; refresh the SOAR maturity
      line.
- [x] 4.4 Sync delta specs into `openspec/specs/` and archive.
