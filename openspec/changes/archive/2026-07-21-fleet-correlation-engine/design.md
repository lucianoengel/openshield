## Context

D103 gave filtered search over peer_alerts. Correlation is the next layer: aggregate many
alerts into an incident by a rule.

## Goals / Non-Goals

**Goals:** a burst-correlation rule (count within window, above a risk floor) producing
incidents, behind the operator gate.

**Non-Goals:** cross-host correlation (no host column); stateful chains; case creation; UI.

## Decisions

**Correlation is a GROUP BY / HAVING over the aggregate.** The burst rule is `GROUP BY
subject_id HAVING count(*) >= min_alerts` within a time window and above a risk floor —
expressed in SQL, bound by parameters (operator input is DATA). An incident carries the
subject, the count, the peak risk, and the first/last timestamps: enough to triage without
reading any evidence (there is none — peer alerts are content-free, D54).

**Temporal-by-subject, because that is what the aggregate supports.** peer_alerts records
the subject and time but not the originating host, so the correlation is a burst for one
subject over time. Cross-host correlation (the same subject on multiple agents) needs a host
column; noted as a follow-up rather than faked.

## Risks / Trade-offs

- **One rule, one shape.** Burst-by-subject is the highest-value first rule; a general
  rules engine (multiple rule types, chaining) is a larger build the incident type is ready
  for.
- **Windowing is a single look-back, not sliding buckets.** Fine for triage; sliding-window
  analytics are a follow-up if needed.
