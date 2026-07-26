## Context

Every existing network detection needs prior knowledge: a feed listing the domain, a signature matching the
payload, a policy naming the destination. Beaconing needs none.

## Goals / Non-Goals

**Goals:** a pure, testable detector; jitter and outage tolerance; per-subject grouping; verified-only
input; evidence with every finding.

**Non-Goals:** process attribution; low-and-slow beacons below the threshold; deciding whether a beacon is
malicious.

## Decisions

### Median absolute deviation, not standard deviation

A standard deviation is dominated by outliers. One long gap — a laptop that slept, a link that dropped —
inflates it enough to push a real beacon below any sensible threshold, which means evading this detector
would be as cheap as missing one check-in. MAD around the median is stable under exactly that, and a
mutation swapping it for a standard deviation makes the jittered-with-outage case fail.

The median is used for the interval for the same reason: one long gap should not move the reported rhythm.

### Grouped per subject

A rhythm is a property of one endpoint talking to one destination. Pooling the fleet's contacts to a shared
destination synthesizes a rhythm nobody exhibits: many hosts polling an update service at staggered offsets
are, in aggregate, a metronome — and on a real network that is most of the traffic.

This was worth a dedicated fixture. The first test set never had two subjects sharing a destination, so a
mutation that pooled them PASSED; a ten-host staggered-polling fixture now catches it.

### The base rate is handled by design, not hoped away

Legitimate software beacons constantly. That is not a tuning problem to be solved later, it is the dominant
case, so three things follow: the alert is **medium** (a detector that cries critical at NTP is muted
within a week), every finding carries **interval, count and regularity** so it is dismissible at a glance,
and the **allowlist is an input** rather than something bolted on. A detector whose output is mostly
known-good gets muted, and a muted detector is worse than none.

### Observation time, not receipt time

A rhythm measured by when the control plane happened to receive telemetry is a rhythm of the transport —
batching, retries and queue drain would create and destroy beacons that no endpoint exhibits.

### The title is a closed label; the destination is not in it

D241's rule: an alert title is a closed-vocabulary label. Putting the destination there would place an
observable into every list that renders a title.

## Risks / Trade-offs

- **False positives dominate by base rate** → medium severity, evidence-carrying, allowlist-first, no
  enforcement. Stated rather than mitigated away.
- **Low-and-slow evades the contact threshold** → inherent: fewer contacts means less measurable rhythm.
  Lowering the threshold trades it for noise, which is the operator's dial, not a fixed answer.
- **A destination reached through a CDN or shared host aggregates unrelated traffic** → not resolved here.

## Migration Plan

Additive; nothing runs it on a timer yet, so a deployment sees no change until it is scheduled.

## Open Questions

- Whether this should run on the existing correlation loop or its own longer cycle — beaconing needs a
  much wider window than burst correlation, so sharing a tick would either starve it or over-run the rest.
