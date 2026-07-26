# response-metrics Specification

## Purpose
Incident response-time measurement (SOAR-6), derived from the timestamps SOAR-2's forward-only lifecycle
was constrained to preserve. Platform lag and analyst time are measured separately, every average is
reported alongside the population it excludes, and nothing is aggregated per named analyst.


### Requirement: Platform lag and analyst response are measured separately

The system SHALL measure three distinct durations and SHALL NOT merge them into a single "response time":
**detection latency** (incident raised minus its first contributing alert), **time to acknowledge**
(acknowledged minus raised) and **time to resolve** (closed minus raised). Detection latency is the
platform's own lag and an analyst cannot influence it; folding it into MTTA would charge a human for a
correlation interval they did not control.

#### Scenario: The three durations are reported independently
- **WHEN** response metrics are computed
- **THEN** detection latency, time-to-acknowledge and time-to-resolve are each reported with their own
  count and percentiles

#### Scenario: Time-to-resolve counts only resolved incidents
- **WHEN** an incident has not reached the closed state
- **THEN** it contributes no time-to-resolve measurement

### Requirement: The excluded population is reported alongside every average

Time-to-acknowledge is computable only for acknowledged incidents and time-to-resolve only for closed
ones. Every report SHALL state how many incidents are EXCLUDED from each measurement. An average over a
small, self-selected subset that is presented without its denominator reads as fleet performance and is
not.

#### Scenario: Unacknowledged incidents are counted as excluded
- **WHEN** some incidents have never been acknowledged
- **THEN** the report states how many were excluded from the time-to-acknowledge measurement

#### Scenario: Unresolved incidents are counted as excluded
- **WHEN** some incidents are not closed
- **THEN** the report states how many were excluded from the time-to-resolve measurement

### Requirement: Metrics are exposed as histograms and as an operator report

The durations SHALL be exposed on the Prometheus endpoint as histograms with cumulative buckets, a sum
and a count, so a rate and an average can be derived by a scraper — and additionally as an
analyst-readable report with counts and percentiles.

#### Scenario: Acknowledging an incident moves the metric
- **WHEN** an incident is acknowledged
- **THEN** the time-to-acknowledge count increases and the corresponding buckets increase

#### Scenario: Buckets are cumulative and consistent
- **WHEN** histogram buckets are emitted
- **THEN** each bucket is at least as large as the one below it and the `+Inf` bucket equals the count

### Requirement: A metrics failure never fails the scrape

If the aggregate cannot be computed, the endpoint SHALL still serve the counters it can and omit the
histograms, rather than returning an error. A monitoring endpoint that fails takes alerting down with it,
turning a reporting problem into an outage in the system that would have reported the outage.

#### Scenario: The endpoint degrades rather than erroring
- **WHEN** the response-metric aggregate cannot be produced
- **THEN** the endpoint still returns 200 with the remaining metrics

### Requirement: Response metrics are not attributed to individual analysts

Reported metrics SHALL be fleet-level aggregates. The system SHALL NOT aggregate response times per named
operator. Attribution stays on the incident, where it serves accountability for a specific decision;
turning it into a per-person score converts an operational measure into workforce surveillance.

#### Scenario: No per-operator aggregate is produced
- **WHEN** response metrics are computed
- **THEN** no output groups durations by the acknowledging or transitioning operator
